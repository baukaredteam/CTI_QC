"""M6.1 test suite — coverage analyzer (core of the hypothesis engine).

Covers:
1. Synthetic cases for all five primary statuses
2. Parent/child MITRE matching (T1204 covered by a rule on T1204.002; no T12040 false match)
3. Multi-rule aggregation (COVERED wins, secondary flags keep the sysmon caveat)
4. Chokepoint bonus (adversary_control LOW → priority × bonus)
5. Acceptance: real full_rules85.yaml rulebook × 3 seeded tenants × a
   TL-2026-1693-style threat (45 TTPs, sectors finance + cryptocurrency)
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

from app.services.constants import strip_yaml_values
from app.services.coverage.analyzer import (
    COVERAGE_GAP,
    COVERED,
    DRL_BLIND,
    FIELD_PARTIAL,
    SYSMON_BLIND,
    analyze_coverage,
)
from app.services.mitre_meta import TTP_TACTICS

# ---------------------------------------------------------------------------
# Synthetic helpers
# ---------------------------------------------------------------------------


def _rule(rule_id, techniques, *, enabled=True, log_source="Microsoft Windows Security Event Log",
          sysmon=False, custom_fields=None):
    return {
        "rule_id": rule_id,
        "enabled": enabled,
        "log_source": log_source,
        "mitre_techniques": techniques,
        "sysmon_required": sysmon,
        "custom_fields": custom_fields or [],
    }


def _cf(name, availability="full", adversary_control="HIGH"):
    return {"name": name, "availability": availability, "adversary_control": adversary_control}


_TENANT_OK = {
    "id": 1, "name": "synthetic", "sector": "finance", "geo": "KZ",
    "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
    "drl_matrix": {"windows_event_log": 3},
}


def _one(report, tid):
    return next(r for r in report.techniques if r.technique_id == tid)


# ---------------------------------------------------------------------------
# 1. Five primary statuses
# ---------------------------------------------------------------------------


def test_covered_status():
    rules = [_rule("R1", ["T1078"], custom_fields=[_cf("usr", "full", "LOW")])]
    rec = _one(analyze_coverage(["T1078"], _TENANT_OK, rules), "T1078")
    assert rec.primary_status == COVERED
    assert rec.covering_rule_ids == ["R1"]
    assert rec.required_log_source == "windows_event_log"
    assert rec.tenant_drl == 3
    assert rec.worst_availability == "full"
    assert rec.secondary_blind_flags == set()


def test_field_partial_status():
    rules = [_rule("R1", ["T1059.001"], custom_fields=[_cf("a", "full"), _cf("cmdline", "partial")])]
    rec = _one(analyze_coverage(["T1059.001"], _TENANT_OK, rules), "T1059.001")
    assert rec.primary_status == FIELD_PARTIAL
    assert rec.worst_availability == "partial"


def test_drl_blind_status():
    tenant = dict(_TENANT_OK, drl_matrix={"windows_event_log": 1})
    rules = [_rule("R1", ["T1078"])]
    rec = _one(analyze_coverage(["T1078"], tenant, rules), "T1078")
    assert rec.primary_status == DRL_BLIND
    assert rec.tenant_drl == 1


def test_sysmon_blind_status():
    # sysmon check comes FIRST: even with good windows_event_log DRL, a
    # sysmon_required rule is blind when drl_matrix has no sysmon key ≥ 2.
    rules = [_rule("R1", ["T1055"], sysmon=True)]
    rec = _one(analyze_coverage(["T1055"], _TENANT_OK, rules), "T1055")
    assert rec.primary_status == SYSMON_BLIND


def test_coverage_gap_status():
    rules = [_rule("R1", ["T1078"])]
    rec = _one(analyze_coverage(["T1486"], _TENANT_OK, rules), "T1486")
    assert rec.primary_status == COVERAGE_GAP
    assert rec.covering_rule_ids == []
    assert rec.required_log_source is None
    assert rec.tenant_drl is None
    assert rec.worst_availability is None
    assert rec.is_chokepoint is False


# ---------------------------------------------------------------------------
# 2. Parent/child MITRE matching
# ---------------------------------------------------------------------------


def test_parent_technique_matched_by_child_rule():
    # Threat T1204 must be covered by a rule on T1204.002 (dot-boundary prefix)
    rules = [_rule("R1", ["T1204.002"])]
    rec = _one(analyze_coverage(["T1204"], _TENANT_OK, rules), "T1204")
    assert rec.primary_status == COVERED
    assert rec.covering_rule_ids == ["R1"]


def test_child_technique_matched_by_parent_rule():
    rules = [_rule("R1", ["T1204"])]
    rec = _one(analyze_coverage(["T1204.002"], _TENANT_OK, rules), "T1204.002")
    assert rec.primary_status == COVERED


def test_no_false_prefix_match():
    # T1204 must NOT match a hypothetical T12040 (dot boundary required)
    rules = [_rule("R1", ["T12040"])]
    rec = _one(analyze_coverage(["T1204"], _TENANT_OK, rules), "T1204")
    assert rec.primary_status == COVERAGE_GAP


def test_disabled_rule_never_covers():
    rules = [_rule("R1", ["T1078"], enabled=False)]
    rec = _one(analyze_coverage(["T1078"], _TENANT_OK, rules), "T1078")
    assert rec.primary_status == COVERAGE_GAP


# ---------------------------------------------------------------------------
# 3. Multi-rule aggregation
# ---------------------------------------------------------------------------


def test_multi_rule_best_status_wins_with_secondary_flags():
    # Same technique covered by one COVERED rule and one SYSMON_BLIND rule:
    # comes out COVERED, secondary flags note the sysmon caveat.
    rules = [
        _rule("R_SYS", ["T1078"], sysmon=True),
        _rule("R_OK", ["T1078"]),
    ]
    rec = _one(analyze_coverage(["T1078"], _TENANT_OK, rules), "T1078")
    assert rec.primary_status == COVERED
    assert set(rec.covering_rule_ids) == {"R_SYS", "R_OK"}
    assert rec.secondary_blind_flags == {SYSMON_BLIND}
    # chosen rule (first with best status) drives the reported log source/drl
    assert rec.required_log_source == "windows_event_log"
    assert rec.tenant_drl == 3


def test_multi_rule_blind_union_minus_primary():
    # FIELD_PARTIAL beats DRL_BLIND; the DRL caveat stays as secondary flag.
    tenant = dict(_TENANT_OK, drl_matrix={"windows_event_log": 3, "proxy_log": 0})
    rules = [
        _rule("R_DRL", ["T1105"], log_source="proxy_log"),
        _rule("R_PART", ["T1105"], custom_fields=[_cf("cmdline", "partial")]),
    ]
    rec = _one(analyze_coverage(["T1105"], tenant, rules), "T1105")
    assert rec.primary_status == FIELD_PARTIAL
    assert rec.secondary_blind_flags == {DRL_BLIND}


# ---------------------------------------------------------------------------
# 4. Chokepoint bonus
# ---------------------------------------------------------------------------


def test_chokepoint_bonus_raises_priority():
    tenant = dict(_TENANT_OK, drl_matrix={"windows_event_log": 1})  # both DRL_BLIND
    rules = [
        _rule("R_CHOKE", ["T1111"], custom_fields=[_cf("usr", "full", "LOW")]),
        _rule("R_PLAIN", ["T1222"], custom_fields=[_cf("cmdline", "full", "HIGH")]),
    ]
    report = analyze_coverage(["T1111", "T1222"], tenant, rules)
    choke, plain = _one(report, "T1111"), _one(report, "T1222")
    assert choke.is_chokepoint is True
    assert plain.is_chokepoint is False
    assert choke.priority == pytest.approx(plain.priority * 1.25)
    assert choke.priority > plain.priority


def test_summary_counts_and_blind_sorting():
    tenant = dict(_TENANT_OK, drl_matrix={"windows_event_log": 3})
    rules = [
        _rule("R1", ["T1078"]),
        _rule("R2", ["T1055"], sysmon=True),
    ]
    report = analyze_coverage(["T1078", "T1055", "T1486"], tenant, rules,
                              tactic_map={"T1078": "persistence", "T1055": "defense-evasion"})
    counts = report.summary.status_counts
    assert counts[COVERED] == 1 and counts[SYSMON_BLIND] == 1 and counts[COVERAGE_GAP] == 1
    # blind spots exclude COVERED and are sorted by priority desc
    assert [r.primary_status for r in report.summary.blind_spots].count(COVERED) == 0
    prios = [r.priority for r in report.summary.blind_spots]
    assert prios == sorted(prios, reverse=True)
    assert report.summary.tactic_coverage["persistence"] == 1.0
    assert report.summary.tactic_coverage["defense-evasion"] == 0.0
    assert report.summary.tactic_coverage["unknown"] == 0.0


# ===========================================================================
# 5. Acceptance — real rulebook fixture × 3 seeded tenants
# ===========================================================================

_FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "full_rules85.yaml"

# Inline seeded tenants matching the M1 smoke profiles (no sysmon key on any).
_TENANTS = [
    {
        "id": 1, "name": "finance", "sector": "finance", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 3, "proxy_log": 2, "email_gateway": 1},
    },
    {
        "id": 2, "name": "energy", "sector": "energy", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 4, "proxy_log": 3, "email_gateway": 3},
    },
    {
        "id": 3, "name": "critical_infrastructure", "sector": "critical_infrastructure", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 1, "proxy_log": 0, "email_gateway": 0},
    },
]

# TL-2026-1693-style normalized threat: 45 TTPs (botnet spread / crypto theft
# campaign), hardcoded from the real bundle; the shared TTP_TACTICS table
# (moved into app/services/mitre_meta.py) supplies the per-technique tactic.
_THREAT = {
    "id": "TL-2026-1693",
    "sectors": ["finance", "cryptocurrency"],
    "regions": ["Global"],
    "ttps": list(TTP_TACTICS),
}


def _load_rulebook():
    data = strip_yaml_values(yaml.safe_load(_FIXTURE.read_text(encoding="utf-8")))
    return data["rules"]


@pytest.mark.skipif(not _FIXTURE.exists(), reason="full_rules85.yaml fixture not present")
def test_acceptance_real_rulebook_three_tenants():
    assert len(_THREAT["ttps"]) == 45
    rulebook = _load_rulebook()
    reports = {}

    for tenant in _TENANTS:
        report = analyze_coverage(_THREAT, tenant, rulebook, tactic_map=TTP_TACTICS)
        reports[tenant["name"]] = report
        counts = report.summary.status_counts

        print(f"\n=== tenant: {tenant['name']} ===")
        print(f"total TTPs: {len(report.techniques)}  covered: {counts[COVERED]}")
        print(f"FIELD_PARTIAL: {counts[FIELD_PARTIAL]}  DRL_BLIND: {counts[DRL_BLIND]}  "
              f"SYSMON_BLIND: {counts[SYSMON_BLIND]}  COVERAGE_GAP: {counts[COVERAGE_GAP]}")
        print("top 5 blind spots by priority:")
        for rec in report.summary.blind_spots[:5]:
            reason = ", ".join(rec.covering_rule_ids) if rec.covering_rule_ids else "no enabled rule covers"
            print(f"  {rec.technique_id:<10} {rec.primary_status:<13} prio={rec.priority:<7} {reason}")
        print("per-tactic coverage ratio:")
        for tactic, ratio in report.summary.tactic_coverage.items():
            print(f"  {tactic}: {ratio}")

    fin = reports["finance"]
    eng = reports["energy"]
    ci = reports["critical_infrastructure"]

    # INC_0021900 technique (T1027, its only coverage) → FIELD_PARTIAL for finance
    t1027 = _one(fin, "T1027")
    assert t1027.primary_status == FIELD_PARTIAL
    assert "INC_0021900" in t1027.covering_rule_ids

    # sysmon_required rule technique (INC_0002400 → T1003.002) → SYSMON_BLIND
    # for finance (no sysmon key in drl_matrix)
    t1003 = _one(fin, "T1003.002")
    assert t1003.primary_status == SYSMON_BLIND
    assert "INC_0002400" in t1003.covering_rule_ids

    # INC_0000100 technique (T1078): COVERED for finance, DRL_BLIND for
    # critical_infrastructure (windows_event_log=1 < 2)
    assert _one(fin, "T1078").primary_status == COVERED
    assert "INC_0000100" in _one(fin, "T1078").covering_rule_ids
    assert _one(ci, "T1078").primary_status == DRL_BLIND

    # Parent/child against the real rulebook: threat T1204 covered via
    # rules on T1204.002 (INC_0001000 / INC_0001100)
    assert _one(fin, "T1204").primary_status == COVERED

    # Finance (sector-matched: finance + cryptocurrency) ranks the same blind
    # technique higher than energy on the same threat
    assert _one(fin, "T1003.002").priority > _one(eng, "T1003.002").priority
    fin_blind_top = fin.summary.blind_spots[0]
    eng_same = _one(eng, fin_blind_top.technique_id)
    assert fin_blind_top.priority > eng_same.priority
