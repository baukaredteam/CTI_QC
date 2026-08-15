"""M6.4 test suite — hypothesis generator + store (tickets 01/02).

Fixture-driven and fully offline, matching the prior art in
``test_m6_coverage.py`` and ``test_management_service.py``: no DB, no network,
no LLM. Covers:

1. ``generate_hypotheses`` seeds from the coverage report's top blind spots
   and returns at most ``max_hypotheses`` proposed records.
2. Determinism: identical bytes across repeated runs.
3. A coverage-gap hypothesis carries the exact gap marker and the status
   ``proposed``.
4. Chokepoints harvest LOW-adversary-control fields for the technique.
5. Store: add/list/get/update with the proposed → validated/rejected
   lifecycle, and JSON serialization round-trip.
"""

from __future__ import annotations

import asyncio
import json
import pathlib

import pytest

from app.schemas.hypothesis import Hypothesis
from app.services.hypothesis_generator import generate_hypotheses
from app.services.hypothesis_store import (
    add_hypothesis,
    clear,
    get_hypothesis,
    list_hypotheses,
    load_from_file,
    save_to_file,
    update_status,
)
from app.services.rules_parser import parse_rules_file
from app.services.tenants_provider import require_tenant
from app.services.threadlinqs_normalizer import normalize_bundle

_RULES_YAML = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "full_rules85.yaml"

_THREAT_BUNDLE = {
    "id": "TL-2026-1693",
    "title": "Sauri",
    "sectors": ["finance", "cryptocurrency"],
    "regions": ["Global"],
    "ttps": ["T1027", "T1003.002", "T1078", "T1204", "T1102", "T1041", "T1486"],
    "iocs": [],
    "actor_confidence": "high",
}


def _rules():
    return parse_rules_file(_RULES_YAML).rules


def _gen(tenant_id: str = "finance", **kwargs):
    return generate_hypotheses(
        threat_id="TL-2026-1693",
        bundle=_THREAT_BUNDLE,
        tenant=require_tenant(tenant_id),
        rules=_rules(),
        **kwargs,
    )


@pytest.fixture(autouse=True)
def _fresh_store(monkeypatch, tmp_path):
    """Point the store at a temp file and reset in-memory state per test."""
    clear()
    monkeypatch.setattr("app.services.hypothesis_store._DEFAULT_FILE", tmp_path / "hypotheses.json")
    yield


@pytest.mark.skipif(not _RULES_YAML.exists() or not _THREAT_BUNDLE, reason="fixtures present")
def test_generator_seeds_top_blind_spots_proposed():
    rows = _gen("finance", max_hypotheses=3)
    assert 1 <= len(rows) <= 3
    for row in rows:
        assert isinstance(row, Hypothesis)
        assert row.status == "proposed"
        assert row.threat_id == "TL-2026-1693"
        assert row.tenant_id == "finance"
        # Priorities descend (top blind spots first).
        priorities = [r.priority for r in rows]
        assert priorities == sorted(priorities, reverse=True)


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="fixture_rules")
def test_generator_determinism():
    first = [row.model_dump() for row in _gen("finance", now="2026-01-01T00:00:00+00:00")]
    second = [row.model_dump() for row in _gen("finance", now="2026-01-01T00:00:00+00:00")]
    assert first == second


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="fixture_rules")
def test_gap_hypothesis_carries_gap_marker_and_chokepoints():
    from app.services.management_service import GAP_MARKER_RU

    rows = _gen("finance", max_hypotheses=10)
    gap = [r for r in rows if r.coverage_status == "COVERAGE_GAP"]
    assert gap, "expected at least one coverage-gap hypothesis among the top blind spots"
    for row in gap:
        assert GAP_MARKER_RU in row.text_ru


def test_store_lifecycle():
    row = _gen("finance", max_hypotheses=1)[0]
    add_hypothesis(row)
    assert get_hypothesis(row.id) is row
    assert list_hypotheses(tenant_id="finance") == [row]
    assert list_hypotheses(status="proposed") == [row]

    validated = update_status(row.id, "validated")
    assert validated.status == "validated"
    assert get_hypothesis(row.id).status == "validated"
    assert list_hypotheses(status="proposed") == []


def test_store_update_status_stamps_updated_at():
    row = _gen("finance", max_hypotheses=1, now="2026-01-01T00:00:00+00:00")[0]
    add_hypothesis(row)
    before = row.updated_at
    updated = update_status(row.id, "rejected")
    assert updated.status == "rejected"
    assert updated.updated_at != before
    assert updated.updated_at > before


def test_generator_relevance_gate_skips_below_threshold():
    """M6.4 spec STEP 4: the scanner only keeps tenants whose relevance ≥ 30."""
    rows = _gen("finance", max_hypotheses=3)
    assert rows
    gated = _gen("finance", max_hypotheses=3, min_relevance=99.0)
    assert gated == []


def test_store_rejects_invalid_transition():
    row = _gen("finance", max_hypotheses=1)[0]
    add_hypothesis(row)
    update_status(row.id, "validated")
    with pytest.raises(ValueError):
        update_status(row.id, "rejected")


def test_store_json_round_trip(tmp_path):
    rows = _gen("finance", max_hypotheses=2)
    for row in rows:
        add_hypothesis(row)
    path = save_to_file(tmp_path / "out.json")
    clear()
    loaded = load_from_file(path)
    assert loaded == len(rows)
    assert get_hypothesis(rows[0].id) is not None


def test_scan_seam_no_network():
    """The async seam runs offline against the canonical bundle."""
    from app.tasks.feed_scanner import scan_feed

    report = asyncio.run(scan_feed(limit=1))
    assert report["threats_scanned"] == 1
    assert report["generated"] >= 1


# ---------------------------------------------------------------------------
# M6.4 enrichment: context fields filled by the generator
# ---------------------------------------------------------------------------


def test_technique_name_and_tactic_populated():
    rows = _gen("finance", max_hypotheses=10)
    for row in rows:
        assert isinstance(row.technique_name, str)
        # The map always resolves a tactic for the known Sauri bundle TTPs.
        assert row.tactic, f"missing tactic for {row.technique_id}"
    named = [r for r in rows if r.technique_name]
    assert named, "expected at least one technique with a resolved name"


def test_threat_context_fields_populated():
    row = _gen("finance", max_hypotheses=1)[0]
    assert row.threat_title == "Sauri"
    assert row.threat_summary
    assert row.sectors == ["finance", "cryptocurrency"]
    # Actor is only filled when the bundle provides attribution.
    assert isinstance(row.actor, str)


def test_iocs_top_n_harvested_from_bundle():
    bundle = dict(_THREAT_BUNDLE)
    bundle["iocs"] = [
        {"type": "domain", "value": "evil.herokuapp.com", "context": "c2"},
        {"type": "ipv4", "value": "203.0.113.7", "context": "c2"},
        {"type": "sha256", "value": "a" * 64, "context": "dropper"},
        {"type": "domain", "value": "drive.google.com", "context": "legit"},
    ]
    row = generate_hypotheses(
        threat_id="TL-2026-1693",
        bundle=bundle,
        tenant=require_tenant("finance"),
        rules=_rules(),
        max_hypotheses=1,
    )[0]
    assert row.iocs
    assert len(row.iocs) <= 5
    for ioc in row.iocs:
        assert ioc.ioc_type
        assert ioc.value
        assert ioc.note_ru


def test_covered_hypothesis_carries_full_evidence_and_sources():
    rows = _gen("finance", max_hypotheses=10)
    covered = [r for r in rows if r.covering_rule_ids]
    assert covered, "no covered hypothesis among top blind spots"
    for row in covered:
        assert row.expected_evidence_ru
        assert row.data_sources


def test_gap_hypothesis_carries_deterministic_expected_evidence():
    rows = _gen("finance", max_hypotheses=20)
    gap = [r for r in rows if r.coverage_status == "COVERAGE_GAP"]
    assert gap, "expected a COVERAGE_GAP hypothesis"
    for row in gap:
        assert row.expected_evidence_ru
        # Evidence names the technique itself (deterministic template).
        assert row.technique_id in row.expected_evidence_ru
        # Candidate chokepoints come from the durable semantic-field replay.
        assert isinstance(row.candidate_chokepoints, list)


def test_generator_determinism_includes_enrichment():
    first = [row.model_dump() for row in _gen("finance", now="2026-01-01T00:00:00+00:00")]
    second = [row.model_dump() for row in _gen("finance", now="2026-01-01T00:00:00+00:00")]
    assert first == second


# ---------------------------------------------------------------------------
# Ticket 03 — blind-spot markers in expected_evidence_ru
# ---------------------------------------------------------------------------

_TEXT = "Ожидаемые свидетельства техники T9999."

# Exact marker constants (R2-Q4; CONTEXT.md glossary vocabulary).
_MARKER_TEXTS = {
    "COVERAGE_GAP": "нет покрывающего правила",
    "DRL_BLIND": "источник не видит событие",
    "FIELD_PARTIAL": "частичное покрытие",
    "SYSMON_BLIND": "Sysmon не охвачен",
}


@pytest.mark.parametrize("status", sorted(_MARKER_TEXTS))
def test_ticket03_marker_constants_exist_with_exact_text(status):
    """The four marker constants exist in the canonical module with the exact
    R2-Q4 text, and the gap marker is the existing GAP_MARKER_RU (no duplicate)."""
    from app.services import management_service as ms

    const = ms.BLIND_MARKER_RU[status]
    assert const == _MARKER_TEXTS[status]
    assert ms.BLIND_MARKER_RU["COVERAGE_GAP"] is ms.GAP_MARKER_RU


@pytest.mark.parametrize("status", sorted(_MARKER_TEXTS))
def test_ticket03_apply_blind_marker_ru_exact_prefix(status):
    """Each non-COVERED status gains its exact prefix, formatted
    "{маркер} — {текст}", applied when assembling expected_evidence_ru."""
    from app.services.hypothesis_generator import _apply_blind_marker_ru

    out = _apply_blind_marker_ru(status, _TEXT)
    assert out == f"{_MARKER_TEXTS[status]} — {_TEXT}"


def test_ticket03_covered_carries_no_marker():
    from app.services.hypothesis_generator import _apply_blind_marker_ru

    out = _apply_blind_marker_ru("COVERED", _TEXT)
    assert out == _TEXT


def test_ticket03_unknown_status_passes_through_unmarked():
    """Unknown/malformed status is never guessed: no marker added, no
    exception (CONTEXT.md policy — statuses come from the analyzer only)."""
    from app.services.hypothesis_generator import _apply_blind_marker_ru

    for status in ("", "totally-bogus", "FIELD_PARTIAL ", "FIELD_PARTIALX"):
        assert _apply_blind_marker_ru(status, _TEXT) == _TEXT
    assert _apply_blind_marker_ru(None, _TEXT) == _TEXT


@pytest.mark.parametrize("status", sorted(_MARKER_TEXTS))
def test_ticket03_marker_application_is_idempotent(status):
    from app.services.hypothesis_generator import _apply_blind_marker_ru

    once = _apply_blind_marker_ru(status, _TEXT)
    twice = _apply_blind_marker_ru(status, once)
    assert twice == once


def test_ticket03_marker_stream_separation_in_generated_rows():
    """P1 split: GAP_MARKER_RU stays in text_ru AND also appears in
    expected_evidence_ru; the other three markers appear ONLY in
    expected_evidence_ru (never in the narrative text stream)."""
    from app.services.management_service import GAP_MARKER_RU

    rows = _gen("finance", max_hypotheses=20)
    assert rows
    other = {_MARKER_TEXTS[s] for s in ("DRL_BLIND", "FIELD_PARTIAL", "SYSMON_BLIND")}
    for row in rows:
        marker = _MARKER_TEXTS.get(row.coverage_status)
        if marker:
            assert row.expected_evidence_ru.startswith(f"{marker} — ")
        if row.coverage_status == "COVERAGE_GAP":
            # P1: the existing gap marker is preserved in text_ru unchanged.
            assert GAP_MARKER_RU in row.text_ru
        if marker != GAP_MARKER_RU:
            # Non-gap markers never leak into the narrative stream.
            for m in other:
                assert m not in row.text_ru
            assert f"{GAP_MARKER_RU} —" not in row.text_ru


# ---------------------------------------------------------------------------
# Ticket 04 — display-only confidence_priority_bonus
# ---------------------------------------------------------------------------

# Canonical high-confidence bundle: the attribution block is the real-bundle
# shape consumed by threadlinqs_normalizer._extract_attribution (the only
# source of NormalizedThreat.actor_confidence). The top-level actor_confidence
# key of _THREAT_BUNDLE is not read by the normalizer.
_HIGH_CONF_BUNDLE = {
    **_THREAT_BUNDLE,
    "attribution": {"threat_actor": "Sauri", "confidence": "high"},
}
# Non-high baseline: no attribution block -> actor_confidence == "".
_NO_CONF_BUNDLE = {**_THREAT_BUNDLE}


def _gen_bundle(bundle: dict, tenant_id: str = "finance", **kwargs):
    return generate_hypotheses(
        threat_id="TL-2026-1693",
        bundle=dict(bundle),
        tenant=require_tenant(tenant_id),
        rules=_rules(),
        **kwargs,
    )


def test_ticket04_high_confidence_bonus_is_priority_times_1_25():
    rows = _gen_bundle(_HIGH_CONF_BUNDLE, max_hypotheses=10)
    assert rows
    for row in rows:
        assert row.confidence_priority_bonus == pytest.approx(row.priority * 1.25)


@pytest.mark.parametrize("confidence", ["medium", "low", "", "unknown", "community"])
def test_ticket04_non_high_confidence_bonus_is_none(confidence):
    bundle = {**_THREAT_BUNDLE, "attribution": {"threat_actor": "Test Actor", "confidence": confidence}}
    rows = _gen_bundle(bundle, max_hypotheses=1)
    assert rows
    for row in rows:
        assert row.confidence_priority_bonus is None


def test_ticket04_original_priority_unchanged_for_high():
    high_rows = _gen_bundle(_HIGH_CONF_BUNDLE, max_hypotheses=10)
    base_rows = _gen_bundle(_NO_CONF_BUNDLE, max_hypotheses=10)
    assert high_rows and base_rows
    # Same coverage facts -> identical priorities and queue ids, with or
    # without the actor-confidence bonus.
    assert [r.priority for r in high_rows] == [r.priority for r in base_rows]
    assert [r.id for r in high_rows] == [r.id for r in base_rows]
    for row in high_rows:
        assert row.confidence_priority_bonus is not None
        assert row.confidence_priority_bonus != row.priority or row.priority == 0.0


def test_ticket04_original_priority_unchanged_for_non_high():
    rows = _gen_bundle(_NO_CONF_BUNDLE, max_hypotheses=10)
    base_rows = _gen("finance", max_hypotheses=10)
    assert [r.priority for r in rows] == [r.priority for r in base_rows]
    for row in rows:
        assert row.confidence_priority_bonus is None


def test_ticket04_output_ordering_unchanged_by_bonus():
    high_rows = _gen_bundle(_HIGH_CONF_BUNDLE, max_hypotheses=10)
    base_rows = _gen_bundle(_NO_CONF_BUNDLE, max_hypotheses=10)
    # Queue order (priority-desc blind spots) is identical with the bonus.
    assert [r.id for r in high_rows] == [r.id for r in base_rows]
    priorities = [r.priority for r in high_rows]
    assert priorities == sorted(priorities, reverse=True)


def test_ticket04_missing_bonus_in_serialized_json_reads_as_none(tmp_path):
    row = _gen_bundle(_HIGH_CONF_BUNDLE, max_hypotheses=1, now="2026-01-01T00:00:00+00:00")[0]
    dump = row.model_dump()
    dump.pop("confidence_priority_bonus", None)
    path = tmp_path / "legacy_hypotheses.json"
    path.write_text(json.dumps([dump], ensure_ascii=False), encoding="utf-8")
    clear()
    assert load_from_file(path) == 1
    loaded = get_hypothesis(row.id)
    assert loaded is not None
    assert loaded.confidence_priority_bonus is None


def test_ticket04_repeated_generation_is_deterministic_including_bonus():
    first = [r.model_dump() for r in _gen_bundle(_HIGH_CONF_BUNDLE, max_hypotheses=5, now="2026-01-01T00:00:00+00:00")]
    second = [r.model_dump() for r in _gen_bundle(_HIGH_CONF_BUNDLE, max_hypotheses=5, now="2026-01-01T00:00:00+00:00")]
    assert first == second
    assert any(r["confidence_priority_bonus"] is not None for r in first)


@pytest.mark.parametrize(
    ("confidence", "expect_bonus"),
    [
        # Existing canonical predicate (hypothesis_generator/management_service):
        # str(confidence).lower() in {"high", "высокая"} — nothing else counts.
        ("high", True),
        ("Высокая", True),
        ("medium", False),
        ("low", False),
        ("", False),
        ("unknown", False),
        ("community", False),
        # Trailing space: _extract_attribution strips whitespace as part of
        # the existing canonical normalization, so this reads as "high".
        ("HIGH ", True),
        ("high!", False),
    ],
)
def test_ticket04_bonus_follows_canonical_confidence_normalization_only(confidence, expect_bonus):
    bundle = {**_THREAT_BUNDLE, "attribution": {"threat_actor": "Test Actor", "confidence": confidence}}
    rows = _gen_bundle(bundle, max_hypotheses=1)
    assert rows
    if expect_bonus:
        assert rows[0].confidence_priority_bonus == pytest.approx(rows[0].priority * 1.25)
    else:
        assert rows[0].confidence_priority_bonus is None


def test_ticket04_bonus_stays_display_only_through_lifecycle():
    rows = _gen_bundle(_HIGH_CONF_BUNDLE, max_hypotheses=1)
    row = rows[0]
    # Sorting is by priority, not by the display bonus.
    assert [r.priority for r in rows] == sorted((r.priority for r in rows), reverse=True)
    add_hypothesis(row)
    validated = update_status(row.id, "validated")
    assert validated.status == "validated"
    assert validated.confidence_priority_bonus == row.confidence_priority_bonus
    assert validated.priority == row.priority


# ---------------------------------------------------------------------------
# Ticket 05 — candidate_chokepoints = technique telemetry templates
# ∩ fields.yaml entries with adversary_control == "LOW" (canonical comparison)
# ---------------------------------------------------------------------------


def _raw_entry(name: str, control: str) -> dict:
    """One raw fields.yaml custom_field row (untrusted QRadar shape);
    canonicalization happens inside parse_fields_catalog."""
    return {
        "name": name,
        "adversary_control": control,
        "availability": "full",
        "requires_gpo": False,
        "notes": "synthetic note",
    }


def _synth_catalog():
    from app.services.mitre_meta import parse_fields_catalog

    raw = [
        _raw_entry("low_field", "LOW"),
        _raw_entry("high_field", "HIGH"),
        _raw_entry("med_field", "MED"),
        _raw_entry("proc_cmdline", "HIGH"),
        _raw_entry("dup_field", "LOW"),
        _raw_entry("dup_field", "LOW"),
        _raw_entry("dup_conflict", "LOW"),
        _raw_entry("dup_conflict", "HIGH"),
        _raw_entry("nocontrol", ""),
    ]
    return parse_fields_catalog({"custom_fields": raw})


_SYNTH_TEMPLATE = (
    "low_field",
    "high_field",
    "med_field",
    "proc_cmdline",
    "dup_field",
    "dup_conflict",
    "nocontrol",
    "missing_field",
)


def _patched_catalog(monkeypatch):
    # Patch the names as bound in hypothesis_generator (from-import rebinding).
    monkeypatch.setattr(
        "app.services.hypothesis_generator.fields_catalog", lambda: _synth_catalog()
    )
    monkeypatch.setattr(
        "app.services.hypothesis_generator._telemetry_fields", lambda tid: _SYNTH_TEMPLATE
    )


def test_ticket05_low_field_in_template_and_catalog_is_candidate(monkeypatch):
    from app.services.hypothesis_generator import _candidate_chokepoints

    _patched_catalog(monkeypatch)
    fields = [c.field for c in _candidate_chokepoints("T9999")]
    assert "low_field" in fields
    assert "missing_field" not in fields


def test_ticket05_high_med_and_conflict_fields_never_candidate(monkeypatch):
    from app.services.hypothesis_generator import _candidate_chokepoints

    _patched_catalog(monkeypatch)
    fields = [c.field for c in _candidate_chokepoints("T9999")]
    assert "high_field" not in fields
    assert "med_field" not in fields
    assert "proc_cmdline" not in fields
    # Contradictory duplicate controls exclude the field entirely (an ambiguous
    # control is never exact LOW).
    assert "dup_conflict" not in fields


def test_ticket05_gap_without_covering_rules_gets_candidates():
    # T1613 exists in no rule and no fixture → COVERAGE_GAP, covering_rule_ids
    # == []; the real template fallback ("proc_cmdline", "dns_rname") ∩ LOW
    # catalog = {"dns_rname"} → candidates exist without covering rules.
    bundle = {**_THREAT_BUNDLE, "ttps": ["T1613"]}
    rows = _gen_bundle(bundle, max_hypotheses=50)
    gap = next(
        r for r in rows if r.coverage_status == "COVERAGE_GAP" and r.technique_id == "T1613"
    )
    assert gap.covering_rule_ids == []
    assert gap.chokepoints == []
    from app.services.mitre_meta import _telemetry_fields, fields_catalog

    catalog = fields_catalog()
    real_low = {
        f
        for f in _telemetry_fields("T1613")
        if (catalog.get(f) or {}).get("adversary_controls") == {"LOW"}
    }
    assert real_low, "fixture precondition: the fallback template must hold a LOW catalog field"
    assert {c.field for c in gap.candidate_chokepoints} == real_low


def test_ticket05_rule_chokepoints_remain_rule_derived():
    from app.services.hypothesis_generator import _chokepoints_for

    baseline = _gen("finance", max_hypotheses=20)
    assert _chokepoints_for("T1059.001", []) == []
    # The rule-derived list is byte-identical to what the generator emitted:
    # rules, never the catalog, are its source.
    rules = _rules()
    for row in baseline:
        assert [
            (c.field, c.note_ru) for c in _chokepoints_for(row.technique_id, rules)
        ] == [(c.field, c.note_ru) for c in row.chokepoints]


def test_ticket05_duplicate_entries_yield_single_deterministic_candidate(monkeypatch):
    from app.services.hypothesis_generator import _candidate_chokepoints

    _patched_catalog(monkeypatch)
    first = [c.field for c in _candidate_chokepoints("T9999")]
    second = [c.field for c in _candidate_chokepoints("T9999")]
    assert first == second
    assert first.count("dup_field") == 1


def test_ticket05_unknown_and_uncontrolled_entries_never_become_low(monkeypatch):
    from app.services.hypothesis_generator import _candidate_chokepoints

    _patched_catalog(monkeypatch)
    fields = [c.field for c in _candidate_chokepoints("T9999")]
    assert fields, "synthetic fixture must produce a non-empty intersection"
    assert "missing_field" not in fields
    assert "nocontrol" not in fields


@pytest.mark.parametrize(
    ("control", "expected"),
    [
        ("LOW", True),
        ("low", True),
        (" LOW", True),
        ("Low", True),
        ("HIGH", False),
        ("MED", False),
        ("", False),
        ("LOW!", False),
        ("MEDIUM", False),
    ],
)
def test_ticket05_exact_low_after_project_normalization_only(monkeypatch, control, expected):
    # Raw YAML values flow through the canonical parse step (strip + upper),
    # the project's existing normalization — the exact LOW comparison runs on
    # the canonicalized value, never on raw synonyms.
    from app.services.mitre_meta import parse_fields_catalog
    from app.services.hypothesis_generator import _candidate_chokepoints

    catalog = parse_fields_catalog({"custom_fields": [_raw_entry("probe", control)]})
    monkeypatch.setattr(
        "app.services.hypothesis_generator.fields_catalog", lambda: catalog
    )
    monkeypatch.setattr(
        "app.services.hypothesis_generator._telemetry_fields", lambda tid: ("probe",)
    )
    fields = [c.field for c in _candidate_chokepoints("T9999")]
    assert ("probe" in fields) is expected


def test_ticket05_bonus_priority_and_ordering_untouched_by_candidates(monkeypatch):
    baseline = _gen("finance", max_hypotheses=10)
    _patched_catalog(monkeypatch)
    patched = _gen("finance", max_hypotheses=10)
    assert [r.id for r in baseline] == [r.id for r in patched]
    assert [r.priority for r in baseline] == [r.priority for r in patched]
    assert [r.confidence_priority_bonus for r in baseline] == [
        r.confidence_priority_bonus for r in patched
    ]
    assert [[(c.field, c.note_ru) for c in r.chokepoints] for r in baseline] == [
        [(c.field, c.note_ru) for c in r.chokepoints] for r in patched
    ]


def test_ticket05_repeated_generation_deterministic_with_candidates():
    bundle = {**_THREAT_BUNDLE, "ttps": ["T1613"]}
    first = [
        r.model_dump() for r in _gen_bundle(bundle, max_hypotheses=10, now="2026-01-01T00:00:00+00:00")
    ]
    second = [
        r.model_dump() for r in _gen_bundle(bundle, max_hypotheses=10, now="2026-01-01T00:00:00+00:00")
    ]
    assert first == second
    gap = next(d for d in first if d["technique_id"] == "T1613")
    assert gap["candidate_chokepoints"]