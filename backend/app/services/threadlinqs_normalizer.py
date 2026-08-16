"""Threadlinqs bundle normalizer.

Takes a raw Threadlinqs bundle and produces:
- IOC list: network + file indicators (blockable)
- Behavioral list: technique tags used as hunt seeds / MITRE hints (not blockable)
- Metadata: sectors, regions, TTPs, actor, confidence

Indicators block is PRIMARY. Narrative mining is secondary (M6).

Real Threadlinqs IOC shape (as of v7.1.0):
  iocs: { network: [{type, value, context}], file: [...], behavioral: [...],
          packages?: [...], techniques?: [...] }
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Sequence

from app.services.ioc_classifier import (
    ClassifiedIOC,
    IOCVerdict,
    classify_ioc,
)

logger = logging.getLogger(__name__)


@dataclass
class NormalizedIOC:
    """A single normalized IOC ready for blocklist consideration."""

    value: str
    ioc_type: str  # "domain", "ipv4", "ipv6", "url", "hash_sha256", etc.
    source: str  # "network" or "file"
    context: str = ""
    classification: ClassifiedIOC | None = None
    confidence: str = "structural"


@dataclass
class BehavioralIndicator:
    """A behavioral technique tag — hunt seed, not a blocklist item."""

    technique_id: str  # e.g. "T1059.001"
    technique_name: str
    context: str = ""


@dataclass
class NormalizedThreat:
    """Fully normalized threat from a Threadlinqs bundle."""

    bundle_id: str
    title: str = ""
    actor: str = ""
    actor_confidence: str = ""
    iocs: list[NormalizedIOC] = field(default_factory=list)
    behavioral: list[BehavioralIndicator] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    raw_bundle: dict[str, Any] = field(default_factory=dict)
    adversary_playbooks: list[str] = field(default_factory=list)
    infrastructure_pivots: list[dict[str, Any]] = field(default_factory=list)
    related_threats: list[str] = field(default_factory=list)


# --- Type mapping for the real Threadlinqs IOC types ---

_NETWORK_IOC_TYPES: dict[str, str] = {
    "ip": "ipv4",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "email": "email",
}

_FILE_IOC_TYPES: dict[str, str] = {
    "sha256": "hash_sha256",
    "sha1": "hash_sha1",
    "md5": "hash_md5",
    "hash": "hash_sha256",
    "filename": "filename",
    "path": "filepath",
    "file": "filename",
}

# MITRE technique ID pattern
_MITRE_RE = re.compile(r"(T\d{4}(?:\.\d{3})?)")


def _normalize_ioc_type(raw_type: str, source_category: str) -> tuple[str, str] | None:
    """Map a raw IOC type to (canonical_type, source).

    Returns None if the type is not an IOC (e.g., technique, command).
    """
    key = raw_type.lower().strip()

    if source_category == "network":
        canonical = _NETWORK_IOC_TYPES.get(key)
        if canonical:
            return canonical, "network"
        # Unknown network type — still treat as network IOC
        if key not in ("technique", "command", "organization"):
            return key, "network"

    if source_category == "file":
        canonical = _FILE_IOC_TYPES.get(key)
        if canonical:
            return canonical, "file"
        if key not in ("technique", "command", "organization"):
            return key, "file"

    # Fallback: check if it's a known IOC type regardless of category
    if key in _NETWORK_IOC_TYPES:
        return _NETWORK_IOC_TYPES[key], "network"
    if key in _FILE_IOC_TYPES:
        return _FILE_IOC_TYPES[key], "file"

    return None


def _extract_iocs_from_category(
    items: list[dict[str, Any]], source_category: str
) -> tuple[list[NormalizedIOC], list[BehavioralIndicator]]:
    """Extract IOCs and behavioral from a single category list."""
    iocs: list[NormalizedIOC] = []
    behavioral: list[BehavioralIndicator] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        raw_type = str(item.get("type", "")).strip()
        value = str(item.get("value", "")).strip()
        context = str(item.get("context", "")).strip()
        if not value:
            continue

        type_result = _normalize_ioc_type(raw_type, source_category)
        if type_result is not None:
            ioc_type, source = type_result
            classified = classify_ioc(value, ioc_type)
            iocs.append(NormalizedIOC(
                value=value,
                ioc_type=ioc_type,
                source=source,
                context=context,
                classification=classified,
            ))
        else:
            # Behavioral: extract MITRE ID if present
            m = _MITRE_RE.search(value)
            technique_id = m.group(1) if m else raw_type
            behavioral.append(BehavioralIndicator(
                technique_id=technique_id,
                technique_name=value,
                context=context,
            ))

    return iocs, behavioral


def _extract_indicators(bundle: dict[str, Any]) -> tuple[list[NormalizedIOC], list[BehavioralIndicator]]:
    """Extract IOCs and behavioral indicators from the bundle's IOC block.

    Supports two shapes:
    1. Category-grouped dict: {network: [...], file: [...], behavioral: [...]}
    2. Flat list of {type, value} dicts (fallback)
    """
    iocs: list[NormalizedIOC] = []
    behavioral: list[BehavioralIndicator] = []

    # Find the IOC block — try "iocs" first (real API), then "indicators" (fallback)
    ioc_block = bundle.get("iocs") or bundle.get("indicators") or bundle.get("data", {}).get("indicators")

    if ioc_block is None:
        return iocs, behavioral

    # Shape 1: category-grouped dict {network: [...], file: [...], behavioral: [...]}
    if isinstance(ioc_block, dict):
        for category in ("network",):
            items = ioc_block.get(category, [])
            if isinstance(items, list):
                cat_iocs, cat_beh = _extract_iocs_from_category(items, "network")
                iocs.extend(cat_iocs)
                behavioral.extend(cat_beh)

        for category in ("file",):
            items = ioc_block.get(category, [])
            if isinstance(items, list):
                cat_iocs, cat_beh = _extract_iocs_from_category(items, "file")
                iocs.extend(cat_iocs)
                behavioral.extend(cat_beh)

        # behavioral, techniques → always behavioral indicators
        for category in ("behavioral", "techniques"):
            items = ioc_block.get(category, [])
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    value = str(item.get("value", "")).strip()
                    context = str(item.get("context", "")).strip()
                    if not value:
                        continue
                    m = _MITRE_RE.search(value)
                    technique_id = m.group(1) if m else value
                    behavioral.append(BehavioralIndicator(
                        technique_id=technique_id,
                        technique_name=value,
                        context=context,
                    ))

        # packages → skip (not IOCs or behavioral)
        return iocs, behavioral

    # Shape 2: flat list of {type, value} dicts
    if isinstance(ioc_block, list):
        for ind in ioc_block:
            if not isinstance(ind, dict):
                continue
            raw_type = str(ind.get("type", "")).strip()
            value = str(ind.get("value", "")).strip()
            context = str(ind.get("context", "")).strip()
            if not value:
                continue

            # Try as IOC first
            type_result = _normalize_ioc_type(raw_type, "network")
            if type_result is None:
                type_result = _normalize_ioc_type(raw_type, "file")

            if type_result is not None:
                ioc_type, source = type_result
                classified = classify_ioc(value, ioc_type)
                iocs.append(NormalizedIOC(
                    value=value,
                    ioc_type=ioc_type,
                    source=source,
                    context=context,
                    classification=classified,
                ))
            else:
                m = _MITRE_RE.search(value)
                technique_id = m.group(1) if m else (ind.get("technique_id", raw_type))
                technique_name = ind.get("technique_name", ind.get("name", value))
                behavioral.append(BehavioralIndicator(
                    technique_id=str(technique_id).strip(),
                    technique_name=str(technique_name).strip(),
                    context=context,
                ))

    return iocs, behavioral


def _extract_techniques(bundle: dict[str, Any]) -> list[BehavioralIndicator]:
    """Extract technique tags from posture/techniques/mitre_attack sections."""
    techniques: list[BehavioralIndicator] = []

    for key in ("posture", "techniques", "ttps", "mitre_attack"):
        section = bundle.get(key)
        if section is None:
            section = bundle.get("data", {}).get(key)
        if section is None:
            continue

        if isinstance(section, list):
            items = section
        elif isinstance(section, dict):
            items = section.get("techniques", section.get("technique_ids", []))
        else:
            continue

        for item in items:
            if isinstance(item, str):
                m = _MITRE_RE.search(item)
                tid = m.group(1) if m else item.strip()
                techniques.append(BehavioralIndicator(
                    technique_id=tid,
                    technique_name=item.strip(),
                ))
            elif isinstance(item, dict):
                raw_id = str(item.get("id", item.get("technique_id", ""))).strip()
                raw_name = str(item.get("name", item.get("technique_name", ""))).strip()
                value = raw_id or raw_name
                m = _MITRE_RE.search(value)
                tid = m.group(1) if m else value
                techniques.append(BehavioralIndicator(
                    technique_id=tid,
                    technique_name=raw_name or tid,
                    context=str(item.get("description", item.get("context", ""))).strip(),
                ))

    return techniques


def _extract_flat_field(bundle: dict[str, Any], *keys: str) -> list[str]:
    """Extract and flatten a field that may be a string, list, or nested."""
    results: list[str] = []
    for key in keys:
        val = bundle.get(key)
        if val is None:
            val = bundle.get("data", {}).get(key)
        if val is None:
            continue
        if isinstance(val, str):
            results.extend(v.strip() for v in val.split(",") if v.strip())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    results.extend(v.strip() for v in item.split(",") if v.strip())
                elif isinstance(item, dict):
                    name = item.get("name", item.get("value", ""))
                    if name:
                        results.append(str(name).strip())
    return list(dict.fromkeys(results))  # dedupe, preserve order


def _extract_attribution(bundle: dict[str, Any]) -> tuple[str, str]:
    """Extract actor name and confidence from attribution section."""
    for key in ("attribution", "actor", "threat_actor"):
        section = bundle.get(key)
        if section is None:
            section = bundle.get("data", {}).get(key)
        if section is None:
            continue
        if isinstance(section, str):
            if section.strip():
                return section.strip(), ""
            continue
        if isinstance(section, dict):
            # Real API: {threat_actor, threat_actor_aliases, nation_state, motivation, confidence}
            actor = str(
                section.get("threat_actor",
                section.get("name",
                section.get("actor", "")))
            ).strip()
            confidence = str(section.get("confidence", "")).strip()
            if actor and actor.lower() not in ("unattributed", "unknown", "none", ""):
                return actor, confidence
    # Fallback: top-level threat_actor string
    ta = bundle.get("threat_actor", "")
    if isinstance(ta, str) and ta.strip() and ta.strip().lower() not in ("unattributed", "unknown"):
        return ta.strip(), ""
    return "", ""


# --- Enrichment blocks (simulations / pivots / similar threats) ---
#
# Contract: missing, None, malformed, or wrong-typed input always returns an
# empty list — never raises. Extracted text is data: it is never evaluated,
# executed, or interpreted as a command.

_SIMULATION_TEXT_KEYS: tuple[str, ...] = ("playbook", "name", "title", "value")
_THREAT_TEXT_KEYS: tuple[str, ...] = ("name", "title", "value", "id")
_PIVOT_SCALAR_TYPES: tuple[type, ...] = (str, int, float, bool)


def _extract_text_items(payload: Any, text_keys: tuple[str, ...]) -> list[str]:
    """Extract trimmed non-empty strings from str / keyed-dict list items."""
    if not isinstance(payload, list):
        return []
    out: list[str] = []
    for item in payload:
        if isinstance(item, str):
            text = item.strip()
        elif isinstance(item, dict):
            text = ""
            for key in text_keys:
                raw = item.get(key)
                if isinstance(raw, str) and raw.strip():
                    text = raw.strip()
                    break
        else:
            continue
        if text:
            out.append(text)
    return list(dict.fromkeys(out))  # dedupe, preserve order


def _extract_simulations(payload: Any) -> list[str]:
    """Simulations block -> adversary playbook names (list[str])."""
    return _extract_text_items(payload, _SIMULATION_TEXT_KEYS)


def _extract_similar_threats(payload: Any) -> list[str]:
    """Similar-threats block -> related threat names (list[str])."""
    return _extract_text_items(payload, _THREAT_TEXT_KEYS)


def _extract_pivots(payload: Any) -> list[dict[str, Any]]:
    """Infrastructure-pivots block -> safe scalar-only dicts (list[dict]).

    Only scalar values (str/int/float/bool) are kept; nested dicts, lists,
    and nulls are dropped, and dicts left empty are excluded. Dedupe is
    canonical (sorted-key JSON), first occurrence wins.
    """
    if not isinstance(payload, list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in payload:
        if not isinstance(item, dict):
            continue
        cleaned: dict[str, Any] = {}
        for key, value in item.items():
            if isinstance(value, str):
                value = value.strip()
                if value:
                    cleaned[key] = value
            elif isinstance(value, _PIVOT_SCALAR_TYPES):
                cleaned[key] = value
        if not cleaned:
            continue
        fingerprint = json.dumps(cleaned, sort_keys=True, ensure_ascii=False)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        out.append(cleaned)
    return out


def normalize_bundle(bundle: dict[str, Any]) -> NormalizedThreat:
    """Normalize a raw Threadlinqs bundle into structured threat data.

    The indicators block is the PRIMARY source:
    - network + file categories → IOC list (blockable, classified by ioc_classifier)
    - behavioral + techniques categories → behavioral list (hunt seeds, MITRE hints)

    Additional metadata extracted from:
    - target_sectors / affected / arsenal → sectors
    - target_regions / regions / geo → regions
    - techniques / mitre_attack → TTPs
    - attribution → actor + confidence
    """
    bundle_id = str(
        bundle.get("id", bundle.get("bundle_id", bundle.get("data", {}).get("id", "unknown")))
    ).strip()
    title = str(
        bundle.get("title", bundle.get("name", bundle.get("data", {}).get("title", "")))
    ).strip()

    # Primary: IOC block (dict-shaped or list-shaped)
    iocs, behavioral_from_indicators = _extract_indicators(bundle)

    # Technique tags from posture/techniques/mitre_attack sections
    behavioral_from_techniques = _extract_techniques(bundle)

    # Merge behavioral, dedupe by technique_id
    seen_techniques: set[str] = set()
    behavioral: list[BehavioralIndicator] = []
    for b in behavioral_from_indicators + behavioral_from_techniques:
        if b.technique_id and b.technique_id not in seen_techniques:
            seen_techniques.add(b.technique_id)
            behavioral.append(b)

    # Sectors
    sectors = _extract_flat_field(
        bundle, "target_sectors", "affected", "arsenal", "sectors", "targeted_sectors"
    )

    # Regions
    regions = _extract_flat_field(
        bundle, "target_regions", "affected", "regions", "targeted_regions", "geo"
    )

    # TTPs (flat list of MITRE technique IDs only)
    ttps: list[str] = []
    seen_ttps: set[str] = set()
    for b in behavioral:
        if b.technique_id and _MITRE_RE.fullmatch(b.technique_id) and b.technique_id not in seen_ttps:
            seen_ttps.add(b.technique_id)
            ttps.append(b.technique_id)

    # Attribution
    actor, actor_confidence = _extract_attribution(bundle)

    # Enrichment blocks: simulations -> playbooks, infrastructure pivots,
    # similar threats -> related threats. Absent/wrong-type -> empty lists.
    simulations = bundle.get("simulations")
    if simulations is None:
        simulations = bundle.get("data", {}).get("simulations")
    pivots = bundle.get("infrastructure_pivots")
    if pivots is None:
        pivots = bundle.get("data", {}).get("infrastructure_pivots")
    similar_threats = bundle.get("similar_threats")
    if similar_threats is None:
        similar_threats = bundle.get("data", {}).get("similar_threats")

    threat = NormalizedThreat(
        bundle_id=bundle_id,
        title=title,
        actor=actor,
        actor_confidence=actor_confidence,
        iocs=iocs,
        behavioral=behavioral,
        sectors=sectors,
        regions=regions,
        ttps=ttps,
        raw_bundle=bundle,
        adversary_playbooks=_extract_simulations(simulations),
        infrastructure_pivots=_extract_pivots(pivots),
        related_threats=_extract_similar_threats(similar_threats),
    )

    logger.info(
        "Normalized bundle %s: %d IOCs, %d behavioral, %d sectors, %d regions, %d TTPs, actor=%s",
        bundle_id, len(iocs), len(behavioral), len(sectors), len(regions), len(ttps), actor or "(none)",
    )

    return threat
