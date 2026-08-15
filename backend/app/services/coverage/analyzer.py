"""Coverage analyzer — M6.1, core of the hypothesis engine. Pure logic, no I/O.

analyze_coverage(threat_ttps, tenant, rulebook) → per-technique coverage records
plus an aggregate summary (counts per status, blind spots by priority, per-tactic
coverage ratio).

Blind-spot types (docs/HYPOTHESIS_ENGINE.md): COVERAGE_GAP, DRL_BLIND,
FIELD_PARTIAL, SYSMON_BLIND. Priority = sector/geo relevance × blind-spot
severity × chokepoint bonus (adversary_control LOW → durable detection).

MITRE matching is parent/child aware on dot boundaries: T1204 matches
T1204.002 (both directions) but never T12040.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from app.services.constants import canonical_log_source
from app.services.relevance_scorer import _get_weights, _region_overlap, _sector_overlap

# --- Statuses ---
COVERED = "COVERED"
FIELD_PARTIAL = "FIELD_PARTIAL"
DRL_BLIND = "DRL_BLIND"
SYSMON_BLIND = "SYSMON_BLIND"
COVERAGE_GAP = "COVERAGE_GAP"

# Best (least blind) first — technique primary_status is the best rule-level
# status across covering rules; COVERAGE_GAP applies only when nothing covers.
_STATUS_RANK: dict[str, int] = {
    COVERED: 0,
    FIELD_PARTIAL: 1,
    DRL_BLIND: 2,
    SYSMON_BLIND: 3,
}

# Blind-spot severity factors: any blind status ranks above COVERED;
# COVERAGE_GAP and SYSMON_BLIND rank highest (nothing can fire at all).
_SEVERITY: dict[str, float] = {
    COVERAGE_GAP: 1.0,
    SYSMON_BLIND: 1.0,
    DRL_BLIND: 0.7,
    FIELD_PARTIAL: 0.4,
    COVERED: 0.1,
}

# Chokepoint bonus: a key field with adversary_control LOW means the detection
# is durable — the adversary cannot cheaply mutate around it.
_CHOKEPOINT_BONUS = 1.25

_DRL_THRESHOLD = 2  # same gate the M1 relevance_scorer uses
_SYSMON_KEY = "sysmon"  # canonical drl_matrix key for Sysmon telemetry

# Relevance floor: an unrelated tenant still gets non-zero priority so blind
# spots never vanish from the ranking entirely.
_RELEVANCE_FLOOR = 0.25


@dataclass(frozen=True)
class TechniqueCoverage:
    """Coverage record for one threat technique against one tenant."""

    technique_id: str
    primary_status: str
    covering_rule_ids: list[str]
    required_log_source: str | None  # canonical, for the chosen rule
    tenant_drl: int | None  # for the chosen rule's log source
    worst_availability: str | None  # worst among chosen rule's custom fields
    is_chokepoint: bool
    secondary_blind_flags: set[str] = field(default_factory=set)
    priority: float = 0.0


@dataclass(frozen=True)
class CoverageSummary:
    """Aggregate summary across all techniques of one threat × tenant."""

    status_counts: dict[str, int]
    blind_spots: list[TechniqueCoverage]  # non-COVERED, sorted by priority desc
    tactic_coverage: dict[str, float]  # tactic → covered/total ratio


@dataclass(frozen=True)
class CoverageReport:
    """Full analyze_coverage result."""

    techniques: list[TechniqueCoverage]
    summary: CoverageSummary


def _mitre_match(threat_tid: str, rule_tid: str) -> bool:
    """Parent/child aware MITRE match on dot boundaries.

    Equal, or one is a dot-boundary prefix of the other:
    T1204 matches T1204.002 (and vice versa); T1204 does NOT match T12040.
    """
    a = threat_tid.upper().strip()
    b = rule_tid.upper().strip()
    if not a or not b:
        return False
    return a == b or b.startswith(a + ".") or a.startswith(b + ".")


def _rule_techniques(rule: Mapping[str, Any]) -> list[str]:
    """Rule technique list — M2 fixture key with M1 fallback."""
    return list(rule.get("mitre_techniques") or rule.get("technique_ids") or [])


def _rule_log_source(rule: Mapping[str, Any]) -> str:
    """Canonical log source of a rule — M2 fixture key with M1 fallback."""
    raw = str(rule.get("log_source") or rule.get("required_log_source") or "")
    return canonical_log_source(raw)


def _rule_status(rule: Mapping[str, Any], drl_matrix: Mapping[str, Any]) -> str:
    """Rule-level status for a tenant, in the mandated evaluation order."""
    if rule.get("sysmon_required") and int(drl_matrix.get(_SYSMON_KEY, 0)) < _DRL_THRESHOLD:
        return SYSMON_BLIND
    if int(drl_matrix.get(_rule_log_source(rule), 0)) < _DRL_THRESHOLD:
        return DRL_BLIND
    for cf in rule.get("custom_fields") or []:
        if str(cf.get("availability", "")).strip().lower() == "partial":
            return FIELD_PARTIAL
    return COVERED


def _worst_availability(rule: Mapping[str, Any]) -> str | None:
    """Worst availability among the rule's custom fields (partial < full)."""
    rank = {"partial": 0, "full": 1}
    worst: str | None = None
    worst_rank = 99
    for cf in rule.get("custom_fields") or []:
        avail = str(cf.get("availability", "")).strip().lower()
        r = rank.get(avail, 0)  # unknown values are treated as worst
        if avail and r < worst_rank:
            worst, worst_rank = avail, r
    return worst


def _is_chokepoint(rule: Mapping[str, Any]) -> bool:
    """True if a key field of the rule has adversary_control LOW."""
    return any(
        str(cf.get("adversary_control", "")).strip().upper() == "LOW"
        for cf in rule.get("custom_fields") or []
    )


def _relevance_factor(threat: Mapping[str, Any], tenant: Mapping[str, Any]) -> float:
    """Sector/geo relevance factor in [_RELEVANCE_FLOOR, 1.0].

    Reuses the relevance_scorer weights and overlap helpers: the sector/region
    portion of the tenant's relevance_config drives the factor; the floor keeps
    unrelated tenants above zero.
    """
    weights = _get_weights(dict(tenant))
    w_sector = weights["sector_weight"]
    w_region = weights["region_weight"]
    denom = w_sector + w_region
    if denom <= 0:
        return 1.0
    sector_hit = 1.0 if _sector_overlap(threat.get("sectors") or [], tenant.get("sector", "")) else 0.0
    region_hit = 1.0 if _region_overlap(threat.get("regions") or [], tenant.get("geo", "")) else 0.0
    ratio = (sector_hit * w_sector + region_hit * w_region) / denom
    return _RELEVANCE_FLOOR + (1.0 - _RELEVANCE_FLOOR) * ratio


def analyze_coverage(
    threat_ttps: Sequence[str] | Mapping[str, Any],
    tenant: Mapping[str, Any],
    rulebook: Sequence[Mapping[str, Any]],
    tactic_map: Mapping[str, str] | None = None,
) -> CoverageReport:
    """Analyze detection coverage of a threat's techniques for one tenant.

    Pure function, no I/O. Args:
        threat_ttps: Either a plain sequence of technique IDs, or a normalized
            threat dict with keys ``ttps`` (required), ``sectors``, ``regions``
            (used for the sector/geo relevance factor; a plain sequence gets a
            neutral relevance of 1.0).
        tenant: Dict with ``sector``, ``geo``, ``relevance_config``, ``drl_matrix``.
        rulebook: Parsed rule dicts (M2 fixture shape: ``rule_id``, ``enabled``,
            ``log_source``, ``mitre_techniques``, ``sysmon_required``,
            ``custom_fields``; M1 key spellings accepted as fallback).
        tactic_map: Optional technique_id → tactic name map for the per-tactic
            coverage ratio; unmapped techniques group under ``unknown``.

    Returns:
        CoverageReport with per-technique records and the aggregate summary.
    """
    if isinstance(threat_ttps, Mapping):
        threat: Mapping[str, Any] = threat_ttps
        ttps = list(threat.get("ttps") or [])
        relevance = _relevance_factor(threat, tenant)
    else:
        ttps = list(threat_ttps)
        relevance = 1.0  # no sector/geo context → neutral relevance

    drl_matrix = tenant.get("drl_matrix") or {}
    enabled_rules = [r for r in rulebook if r.get("enabled", True)]
    tactic_map = tactic_map or {}

    records: list[TechniqueCoverage] = []
    for tid in ttps:
        tid_norm = str(tid).upper().strip()

        # All enabled rules covering this technique (parent/child aware),
        # each with its rule-level status; rulebook order is preserved.
        covering: list[tuple[Mapping[str, Any], str]] = [
            (rule, _rule_status(rule, drl_matrix))
            for rule in enabled_rules
            if any(_mitre_match(tid_norm, rt) for rt in _rule_techniques(rule))
        ]

        if not covering:
            primary = COVERAGE_GAP
            chosen = None
            secondary: set[str] = set()
        else:
            # Best (least blind) status wins; chosen rule = first achieving it.
            primary = min((status for _, status in covering), key=_STATUS_RANK.__getitem__)
            chosen = next(rule for rule, status in covering if status == primary)
            # Union of blind statuses seen across covering rules, minus the
            # primary itself — so a COVERED technique still carries e.g. the
            # sysmon caveat of a secondary blind rule.
            secondary = {s for _, s in covering if s != COVERED} - {primary}

        is_choke = _is_chokepoint(chosen) if chosen is not None else False
        priority = round(
            relevance * _SEVERITY[primary] * (_CHOKEPOINT_BONUS if is_choke else 1.0), 4
        )

        records.append(TechniqueCoverage(
            technique_id=tid_norm,
            primary_status=primary,
            covering_rule_ids=[str(r.get("rule_id") or r.get("id") or "") for r, _ in covering],
            required_log_source=_rule_log_source(chosen) if chosen is not None else None,
            tenant_drl=int(drl_matrix.get(_rule_log_source(chosen), 0)) if chosen is not None else None,
            worst_availability=_worst_availability(chosen) if chosen is not None else None,
            is_chokepoint=is_choke,
            secondary_blind_flags=secondary,
            priority=priority,
        ))

    # --- Aggregate summary ---
    status_counts: dict[str, int] = {
        s: 0 for s in (COVERED, FIELD_PARTIAL, DRL_BLIND, SYSMON_BLIND, COVERAGE_GAP)
    }
    for rec in records:
        status_counts[rec.primary_status] += 1

    blind_spots = sorted(
        (rec for rec in records if rec.primary_status != COVERED),
        key=lambda rec: rec.priority,
        reverse=True,
    )

    tactic_totals: dict[str, int] = {}
    tactic_covered: dict[str, int] = {}
    for rec in records:
        tactic = tactic_map.get(rec.technique_id, "unknown")
        tactic_totals[tactic] = tactic_totals.get(tactic, 0) + 1
        if rec.primary_status == COVERED:
            tactic_covered[tactic] = tactic_covered.get(tactic, 0) + 1
    tactic_coverage = {
        tactic: round(tactic_covered.get(tactic, 0) / total, 4)
        for tactic, total in sorted(tactic_totals.items())
    }

    return CoverageReport(
        techniques=records,
        summary=CoverageSummary(
            status_counts=status_counts,
            blind_spots=blind_spots,
            tactic_coverage=tactic_coverage,
        ),
    )
