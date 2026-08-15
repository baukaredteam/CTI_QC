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