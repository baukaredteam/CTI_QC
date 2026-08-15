"""Relevance scorer — pure functions, no I/O.

score_threat(threat, tenant) → zone result with numeric score + zone label.
visible_ttps(threat, tenant, rulebook) → TTPs visible to a tenant, counting
    a TTP only if an enabled rule covers it AND the tenant DRL for that
    rule's required log source ≥ 2.

Sector/region normalization: canonical mapping so "financial services" matches
"finance" tenant, "criticalinfrastructure" matches "critical_infrastructure", etc.
"Global"/"Worldwide" region matches any tenant geo (full region_weight awarded).

Actor confidence adjustment: HIGH → +10, MEDIUM → 0, LOW → −10 applied to
final score (clamped 0–100). Documented design choice: actor attribution
confidence directly affects the relevance signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class ZoneResult:
    """Scoring result for one threat × one tenant."""

    tenant_id: int
    tenant_name: str
    sector: str
    score: float  # 0.0 – 100.0
    zone: str  # "red", "amber", "green"
    matching_sectors: list[str]
    matching_regions: list[str]
    visible_ttp_count: int
    total_ttp_count: int
    ioc_count: int


@dataclass(frozen=True)
class VisibleTTP:
    """A TTP that is visible to a tenant based on rule coverage + DRL."""

    technique_id: str
    covering_rule_id: str
    required_log_source: str
    tenant_drl: int


# --- Canonical sector map ---
# Maps common Threadlinqs sector strings to canonical tenant sector names.
# Lookup: lowercase + strip + collapse whitespace/hyphens/underscores → canonical.

_SECTOR_CANONICAL: dict[str, str] = {
    "finance": "finance",
    "financial": "finance",
    "financialservices": "finance",
    "financial services": "finance",
    "financial-services": "finance",
    "financial_services": "finance",
    "banking": "finance",
    "cryptocurrency": "finance",
    "fintech": "finance",
    "energy": "energy",
    "energysector": "energy",
    "energy sector": "energy",
    "energy-sector": "energy",
    "oil": "energy",
    "oilandgas": "energy",
    "oil and gas": "energy",
    "oil-and-gas": "energy",
    "utilities": "energy",
    "power": "energy",
    "criticalinfrastructure": "critical_infrastructure",
    "critical infrastructure": "critical_infrastructure",
    "critical-infrastructure": "critical_infrastructure",
    "critical_infrastructure": "critical_infrastructure",
    "industrialcontrolsystems": "critical_infrastructure",
    "ics": "critical_infrastructure",
    "scada": "critical_infrastructure",
    "ot": "critical_infrastructure",
    "water": "critical_infrastructure",
    "transportation": "critical_infrastructure",
    "telecom": "critical_infrastructure",
    "telecommunications": "critical_infrastructure",
    # M6.5 client sectors — canonical keys the new tenants' relevance weights key on.
    "nuclear": "nuclear",
    "nuclearsector": "nuclear",
    "nuclear industry": "nuclear",
    "metals": "metals",
    "metal": "metals",
    "mining": "metals",
    "electricity": "electricity",
    "electric": "electricity",
    "electricitysector": "electricity",
    "oil_and_gas": "oil_and_gas",
    "gas": "gas",
    "natural gas": "gas",
    "naturalgas": "gas",
}

# Regions treated as "global" (match any tenant geo, full region_weight)
_GLOBAL_REGIONS = frozenset({
    "global", "worldwide", "all", "universal", "international",
})


def _canonicalize_sector(raw: str) -> str:
    """Normalize a sector string to a canonical form."""
    normalized = raw.lower().strip()
    # Try direct lookup
    if normalized in _SECTOR_CANONICAL:
        return _SECTOR_CANONICAL[normalized]
    # Collapse separators and retry
    collapsed = re.sub(r"[-_\s]+", "", normalized)
    if collapsed in _SECTOR_CANONICAL:
        return _SECTOR_CANONICAL[collapsed]
    # Return lowercase original if no match
    return normalized


def _weighted_sector_overlap(
    threat_sectors: Sequence[str], tenant: dict[str, Any]
) -> tuple[list[str], float]:
    """Weighted sector match for tenants that define ``sector_weights``.

    A tenant like ``nuclear`` maps related sectors to relative weights
    (e.g. ``{"nuclear": 40, "energy": 20}``): a nuclear threat scores full
    (40/40 = 1.0), an energy threat half (20/40 = 0.5), an unrelated sector 0.
    Without ``sector_weights`` the caller keeps the legacy binary match.
    """
    weights = {
        _canonicalize_sector(key): float(value)
        for key, value in (tenant.get("sector_weights") or {}).items()
    }
    if not weights:
        return [], 0.0
    top = max(weights.values())
    if top <= 0:
        return [], 0.0
    best = 0.0
    matches: list[str] = []
    for sector in threat_sectors:
        weight = weights.get(_canonicalize_sector(sector), 0.0)
        if weight > 0 and sector not in matches:
            matches.append(sector)
            best = max(best, weight)
    if not matches:
        return [], 0.0
    return matches, best / top


def _sector_overlap(
    threat_sectors: Sequence[str], tenant_sector: str
) -> list[str]:
    """Find sectors in common between threat and tenant using canonical mapping."""
    if not tenant_sector:
        return []
    tenant_canonical = _canonicalize_sector(tenant_sector)
    matches = []
    for s in threat_sectors:
        threat_canonical = _canonicalize_sector(s)
        if threat_canonical == tenant_canonical:
            matches.append(s)
    return matches


def _region_overlap(
    threat_regions: Sequence[str], tenant_geo: str
) -> list[str]:
    """Find regions in common between threat and tenant.

    Design choice: "Global"/"Worldwide" matches any tenant geo with full
    region_weight — a global threat is relevant to every tenant.
    """
    if not tenant_geo:
        return []
    tenant_lower = tenant_geo.lower().strip()
    matches = []
    for r in threat_regions:
        r_lower = r.lower().strip()
        if r_lower in _GLOBAL_REGIONS:
            matches.append(r)
        elif r_lower == tenant_lower or tenant_lower in r_lower or r_lower in tenant_lower:
            matches.append(r)
    return matches


_DEFAULT_WEIGHTS = {
    "sector_weight": 30.0,
    "region_weight": 20.0,
    "ttp_weight": 35.0,
    "ioc_weight": 15.0,
}

_DRL_THRESHOLD = 2  # Minimum DRL for a log source to count a TTP as visible

# Actor confidence adjustment: applied to final score before clamping.
_CONFIDENCE_ADJUSTMENT = {
    "high": 10.0,
    "medium": 0.0,
    "low": -10.0,
}


def _get_weights(tenant: dict[str, Any]) -> dict[str, float]:
    """Extract relevance weights from tenant config, with defaults."""
    config = tenant.get("relevance_config") or {}
    return {
        k: float(config.get(k, v))
        for k, v in _DEFAULT_WEIGHTS.items()
    }


def _score_to_zone(score: float) -> str:
    """Map a numeric score to a zone label."""
    if score >= 70.0:
        return "red"
    if score >= 40.0:
        return "amber"
    return "green"


def visible_ttps(
    threat_ttps: Sequence[str],
    tenant: dict[str, Any],
    rulebook: Sequence[dict[str, Any]],
) -> list[VisibleTTP]:
    """Determine which TTPs are visible to a tenant.

    A TTP is visible if:
    1. At least one ENABLED rule in the rulebook covers it.
    2. The tenant's DRL for that rule's required log source is ≥ 2.
    """
    drl_matrix = tenant.get("drl_matrix") or {}
    threat_set = set(t.upper().strip() for t in threat_ttps)
    visible: list[VisibleTTP] = []
    seen: set[str] = set()

    for rule in rulebook:
        if not rule.get("enabled", True):
            continue

        rule_techniques = set(
            t.upper().strip() for t in (rule.get("technique_ids") or [])
        )
        log_source = str(rule.get("required_log_source", "")).strip()
        drl = int(drl_matrix.get(log_source, 0))

        if drl < _DRL_THRESHOLD:
            continue

        for tid in threat_set & rule_techniques:
            if tid not in seen:
                seen.add(tid)
                visible.append(VisibleTTP(
                    technique_id=tid,
                    covering_rule_id=str(rule.get("id", "")),
                    required_log_source=log_source,
                    tenant_drl=drl,
                ))

    return visible


def score_threat(
    threat: dict[str, Any],
    tenant: dict[str, Any],
    rulebook: Sequence[dict[str, Any]] | None = None,
) -> ZoneResult:
    """Score a normalized threat against a tenant profile.

    Args:
        threat: Dict with keys: sectors, regions, ttps, iocs, actor_confidence.
        tenant: Dict with keys: id, name, sector, geo, relevance_config, drl_matrix.
        rulebook: Optional rule list for visible_ttps. If None, all TTPs count.

    Returns:
        ZoneResult with score, zone, and breakdown.
    """
    weights = _get_weights(tenant)

    threat_sectors = threat.get("sectors") or []
    threat_regions = threat.get("regions") or []
    threat_ttps = threat.get("ttps") or []
    threat_iocs = threat.get("iocs") or []

    # Sector overlap (canonical matching, weighted for multi-sector tenants)
    weighted_sectors, weighted_score = _weighted_sector_overlap(threat_sectors, tenant)
    if weighted_sectors:
        matching_sectors = weighted_sectors
        sector_score = weighted_score
    else:
        matching_sectors = _sector_overlap(threat_sectors, tenant.get("sector", ""))
        sector_score = 1.0 if matching_sectors else 0.0

    # Region overlap (with Global matching)
    matching_regions = _region_overlap(threat_regions, tenant.get("geo", ""))
    region_score = 1.0 if matching_regions else 0.0

    # TTP visibility
    total_ttps = len(threat_ttps)
    if rulebook is not None and total_ttps > 0:
        vis = visible_ttps(threat_ttps, tenant, rulebook)
        visible_count = len(vis)
    elif total_ttps > 0:
        visible_count = total_ttps  # No rulebook → all TTPs count
    else:
        visible_count = 0

    ttp_score = (visible_count / max(total_ttps, 1))

    # IOC volume (normalize: cap at 50 IOCs for full score)
    ioc_count = len(threat_iocs) if isinstance(threat_iocs, list) else int(threat_iocs)
    ioc_score = min(ioc_count / 50.0, 1.0)

    # Weighted sum
    raw = (
        sector_score * weights["sector_weight"]
        + region_score * weights["region_weight"]
        + ttp_score * weights["ttp_weight"]
        + ioc_score * weights["ioc_weight"]
    )
    total_weight = sum(weights.values())
    final_score = round((raw / total_weight) * 100.0, 1) if total_weight > 0 else 0.0

    # Actor confidence adjustment: HIGH +10, MEDIUM 0, LOW -10
    actor_confidence = str(threat.get("actor_confidence", "")).strip().lower()
    adjustment = _CONFIDENCE_ADJUSTMENT.get(actor_confidence, 0.0)
    final_score = final_score + adjustment

    # Clamp to 0–100
    final_score = min(max(final_score, 0.0), 100.0)

    return ZoneResult(
        tenant_id=int(tenant.get("id", 0)),
        tenant_name=str(tenant.get("name", "")),
        sector=str(tenant.get("sector", "")),
        score=final_score,
        zone=_score_to_zone(final_score),
        matching_sectors=matching_sectors,
        matching_regions=matching_regions,
        visible_ttp_count=visible_count,
        total_ttp_count=total_ttps,
        ioc_count=ioc_count,
    )
