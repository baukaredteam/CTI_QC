"""Ticket 11.1 — red tests: the recorded Threadlinqs v7.1.0 live envelope is
converted to the canonical flat input at the flatten_bundle seam.

The live ``get_threat_hunting_bundle`` envelope shape (recorded in
``backend/scripts/smoke_threadlinqs.py``, ``_process_bundle``) nests the
threat record under ``threat`` and carries ``mitre_technique_ids`` /
``mitre_tactic_ids`` / enrichment blocks at the TOP level:

    {threat, iocs, detections, simulations, similar_threats,
     infrastructure_pivots, mitre_technique_ids, mitre_tactic_ids, ...}

The canonical flat input consumed by ``normalize_bundle`` /
``generate_hypotheses`` spells technique IDs as ``ttps`` / ``techniques``
records. Without the Ticket 11.1 adapter, flattening the live envelope loses
the technique IDs and the generator emits zero hypotheses.

This module drives the seam with the recorded shape (sanitized values — no
secrets, no real IOC data) and asserts the canonical conversion contract.
"""

from __future__ import annotations

import asyncio
import pathlib

import pytest

from app.services.hypothesis_generator import generate_hypotheses
from app.services.hypothesis_store import clear, save_to_file
from app.services.management_service import flatten_bundle
from app.services.rules_parser import parse_rules_file
from app.services.tenants_provider import require_tenant
from app.services.threadlinqs_normalizer import normalize_bundle
from app.tasks.feed_scanner import scan_feed

_RULES_YAML = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "full_rules85.yaml"

# ---------------------------------------------------------------------------
# Recorded live v7.1.0 envelope — keys copied from the smoke script's live
# output (``Bundle keys`` + the documented shape at smoke_threadlinqs.py:250);
# values sanitized: no API keys, no live IOC values, no attribution facts.
# ---------------------------------------------------------------------------

_LIVE_BUNDLE_ENVELOPE: dict = {
    "threat": {
        "id": "TL-2026-1693",
        "title": "Sauri",
        "description": "Sanitized threat dossier shape",
        "mitre_technique_ids": ["T1027", "T1078", "T1003.002"],
        "mitre_tactic_ids": ["TA0005", "TA0002", "TA0006"],
        "mitre_attack": {"technique_ids": ["T1027", "T1078"]},
        "target_sectors": ["finance", "cryptocurrency"],
        "target_regions": ["Global"],
        "attribution": {"threat_actor": "Sauri", "confidence": "high"},
    },
    "iocs": {
        "network": [{"type": "ipv4", "value": "203.0.113.7"}],
        "file": [{"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
        "behavioral": [{"value": "obfuscated payload", "context": "sanitized"}],
    },
    "detections": [{"name": "Sanitized detection rule", "technique_id": "T1027"}],
    "simulations": [{"playbook": "Ransomware deployment drill"}, {"playbook": "C2 beaconing drill"}],
    "similar_threats": [{"name": "Kasablanka"}, {"name": "Sandworm"}],
    "infrastructure_pivots": [{"ip": "203.0.113.10", "port": 443}],
    "mitre_technique_ids": [
        "T1027", "T1078", "T1003.002", "T1204", "T1102", "T1041", "T1486",
    ],
    "mitre_tactic_ids": ["TA0005", "TA0002", "TA0006", "TA0001", "TA0011", "TA0010", "TA0040"],
}


def _rules():
    return parse_rules_file(_RULES_YAML).rules


def _finance_tenant() -> dict:
    return require_tenant("finance")


# ---------------------------------------------------------------------------
# RED: the recorded envelope currently loses technique IDs at the seam
# ---------------------------------------------------------------------------


def test_red_flatten_live_envelope_keeps_mitre_technique_ids():
    """The recorded live envelope must normalize to the canonical TTP list.

    Before the Ticket 11.1 adapter this yields an empty ``ttps`` list: the
    technique IDs live under ``threat.mitre_technique_ids`` / the top-level
    ``mitre_technique_ids`` key, neither of which the canonical extractor
    reads, so the generator has no hunt seeds.
    """
    flat = flatten_bundle(dict(_LIVE_BUNDLE_ENVELOPE))
    normalized = normalize_bundle(dict(flat))
    assert normalized.ttps, (
        "live envelope lost all technique IDs at the flatten seam: %r"
        % getattr(normalized, "ttps", None)
    )
    assert "T1027" in normalized.ttps
    assert "T1486" in normalized.ttps


def test_red_flatten_live_envelope_preserves_nested_threat_identity():
    """Merge the ``threat`` sub-dict so id/title/sectors survive flattening."""
    flat = flatten_bundle(dict(_LIVE_BUNDLE_ENVELOPE))
    assert flat.get("id") == "TL-2026-1693"
    assert flat.get("title") == "Sauri"
    assert "finance" in (flat.get("sectors") or [])


def test_red_flatten_live_envelope_preserves_enrichment_blocks():
    """simulations / similar_threats / infrastructure_pivots must survive.

    These top-level envelope blocks are the enrichment inputs the generator
    and the MCP enricher consume; dropping them starves the enrichment seam.
    """
    flat = flatten_bundle(dict(_LIVE_BUNDLE_ENVELOPE))
    assert flat.get("simulations")
    assert flat.get("similar_threats")
    assert flat.get("infrastructure_pivots")


# ---------------------------------------------------------------------------
# Ticket 11.2 — empty-block precedence (Part A)
# ---------------------------------------------------------------------------

_ENVELOPE_WITH_EMPTY_NESTED: dict = {
    "threat": {
        "id": "TL-TEST",
        "title": "Test Threat",
        "simulations": [],
        "similar_threats": [],
        "infrastructure_pivots": [],
        "iocs": {"network": [], "file": []},
    },
    "simulations": [{"playbook": "Ransomware drill"}, {"playbook": "C2 beaconing"}],
    "similar_threats": [{"name": "Kasablanka"}, {"name": "Sandworm"}],
    "infrastructure_pivots": [{"ip": "10.0.0.1"}],
    "iocs": {"network": [{"type": "ipv4", "value": "10.0.0.2"}], "file": []},
    "mitre_technique_ids": ["T1027", "T1486"],
    "mitre_tactic_ids": ["TA0005"],
}


def test_flatten_bundle_promotes_top_level_block_when_nested_is_empty():
    """Top-level enrichment blocks must be promoted when nested value is empty.

    Ticket 11.2: the live v7.1.0 envelope carries empty lists in the threat
    sub-dict and populated lists at the top level. The adapter must prefer the
    non-empty top-level value.
    """
    flat = flatten_bundle(dict(_ENVELOPE_WITH_EMPTY_NESTED))
    assert flat.get("simulations") == [{"playbook": "Ransomware drill"}, {"playbook": "C2 beaconing"}]
    assert flat.get("similar_threats") == [{"name": "Kasablanka"}, {"name": "Sandworm"}]
    assert flat.get("infrastructure_pivots") == [{"ip": "10.0.0.1"}]


def test_flatten_bundle_preserves_non_empty_nested_block():
    """Non-empty nested value must NOT be overwritten by top-level value."""
    envelope = {
        "threat": {
            "id": "TL-TEST",
            "simulations": [{"playbook": "Nested Sim"}],
            "similar_threats": [{"name": "Nested Threat"}],
        },
        "simulations": [{"playbook": "Top Sim"}],
        "similar_threats": [{"name": "Top Threat"}],
        "infrastructure_pivots": [{"ip": "10.0.0.1"}],
        "iocs": {},
    }
    flat = flatten_bundle(dict(envelope))
    assert flat.get("simulations") == [{"playbook": "Nested Sim"}]
    assert flat.get("similar_threats") == [{"name": "Nested Threat"}]
    assert flat.get("infrastructure_pivots") == [{"ip": "10.0.0.1"}]


def test_flatten_bundle_handles_none_and_empty_dict():
    """None and {} in nested block must be treated as empty (promote top-level)."""
    envelope = {
        "threat": {
            "id": "TL-TEST",
            "simulations": None,
            "similar_threats": {},
            "infrastructure_pivots": [],
        },
        "simulations": [{"playbook": "Top Sim"}],
        "similar_threats": [{"name": "Top Threat"}],
        "infrastructure_pivots": [{"ip": "10.0.0.1"}],
        "iocs": {},
    }
    flat = flatten_bundle(dict(envelope))
    assert flat.get("simulations") == [{"playbook": "Top Sim"}]
    assert flat.get("similar_threats") == [{"name": "Top Threat"}]
    assert flat.get("infrastructure_pivots") == [{"ip": "10.0.0.1"}]


def test_flatten_bundle_missing_top_level_does_not_invent_data():
    """When both nested and top-level are absent, no synthetic data is created."""
    envelope = {
        "threat": {"id": "TL-TEST"},
        "iocs": {},
    }
    flat = flatten_bundle(dict(envelope))
    assert flat.get("simulations") is None or flat.get("simulations") == []
    assert flat.get("similar_threats") is None or flat.get("similar_threats") == []
    assert flat.get("infrastructure_pivots") is None or flat.get("infrastructure_pivots") == []


def test_flatten_bundle_flat_bundle_remains_idempotent():
    """Existing offline canonical flat bundle passes through unchanged."""
    flat_input = {
        "id": "TL-2026-1693",
        "title": "Sauri",
        "sectors": ["finance"],
        "regions": ["Global"],
        "ttps": ["T1027", "T1486"],
        "techniques": [{"id": "T1027", "tactic": "defense-evasion"}],
        "iocs": {"network": [], "file": []},
        "simulations": [{"playbook": "Drill"}],
        "similar_threats": [{"name": "Kasablanka"}],
        "infrastructure_pivots": [{"ip": "10.0.0.1"}],
    }
    flat = flatten_bundle(dict(flat_input))
    assert flat["id"] == "TL-2026-1693"
    assert flat["ttps"] == ["T1027", "T1486"]
    assert flat["simulations"] == [{"playbook": "Drill"}]
    assert flat["similar_threats"] == [{"name": "Kasablanka"}]
    assert flat["infrastructure_pivots"] == [{"ip": "10.0.0.1"}]


def test_flatten_bundle_does_not_mutate_input():
    """The input mapping must not be mutated by flatten_bundle."""
    envelope = dict(_ENVELOPE_WITH_EMPTY_NESTED)
    original_simulations = envelope["simulations"]
    original_threat_simulations = envelope["threat"]["simulations"]
    flatten_bundle(envelope)
    assert envelope["simulations"] is original_simulations
    assert envelope["threat"]["simulations"] is original_threat_simulations


def test_flatten_bundle_preserves_technique_union_dedupe_order():
    """Technique IDs from all sources are merged, deduped, order-preserving."""
    envelope = {
        "threat": {
            "id": "TL-TEST",
            "mitre_technique_ids": ["T1027", "T1078"],
            "mitre_attack": {"technique_ids": ["T1027", "T1003.002"]},
        },
        "mitre_technique_ids": ["T1078", "T1486", "T1027"],
        "iocs": {},
    }
    flat = flatten_bundle(dict(envelope))
    assert flat["ttps"] == ["T1027", "T1078", "T1003.002", "T1486"]


# ---------------------------------------------------------------------------
# Ticket 11.1 — existing RED tests (kept for regression)
# ---------------------------------------------------------------------------


def test_red_scan_feed_live_envelope_generates_hypotheses(tmp_path, monkeypatch):
    """scan_feed with the recorded live envelope must produce > 0 hypotheses.

    Before the adapter the live envelope's technique IDs are lost at the
    flatten seam, the coverage analyzer sees no blind spots, and the scan
    persists zero hypotheses. This is the GATE (a) live acceptance criterion
    (Ticket 11): populated MCP fields require hunt seeds to exist at all.
    """
    clear()
    monkeypatch.setattr(
        "app.services.hypothesis_store._DEFAULT_FILE",
        tmp_path / "hypotheses.json",
    )

    async def _fetch_recent(_limit: int) -> list[dict[str, str]]:
        return [{"threat_id": "TL-2026-1693"}]

    async def _load_bundle(threat_id: str) -> dict:
        return dict(_LIVE_BUNDLE_ENVELOPE)

    try:
        report = asyncio.run(
            scan_feed(
                fetch_recent=_fetch_recent,
                bundle_loader=_load_bundle,
                limit=1,
                tenants=[_finance_tenant()],
                store_path=tmp_path / "hypotheses.json",
            )
        )
    finally:
        clear()
    assert report["generated"] > 0, "live envelope scan produced zero hypotheses: %r" % report
    assert report["threats_scanned"] == 1
    assert report["skipped"] == 0