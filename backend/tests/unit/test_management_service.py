"""M6.3 test suite — management service orchestrator (ticket 04).

Fixture-driven and fully offline, matching the prior art in
``test_m6_coverage.py``: no DB, no network, no LLM. The deterministic
template path is the only thing asserted (spec: "the deterministic fallback
is what is asserted").

Covers:
1. ``build_summary`` returns a summary with a Russian BLUF and hypotheses
   seeded from the priority-sorted top-N coverage blind spots.
2. Hypothesis ordering matches the underlying coverage priority ranking.
3. A covered hypothesis carries its covering rules + a copy-ready AQL bundle.
4. A hypothesis with no covering rule carries the exact
   «нет покрывающего правила» gap marker (COVERAGE_GAP).
5. Per-hypothesis Admiralty codes, secondary blind flags and chokepoint marker.
6. Determinism: identical bytes across repeated builds (hard requirement).
7. Orchard ``summary`` async seam with default + explicit tenant.
"""

from __future__ import annotations

import asyncio
import pathlib

import pytest

from app.services.management_service import (
    GAP_MARKER_RU,
    build_summary,
    summary,
)
from app.services.rules_parser import parse_rules_file
from app.services.bb_resolver import load_shared_bbs
from app.services.tenants_provider import active_tenant_id, require_tenant

# ---------------------------------------------------------------------------
# Fixture hooks (offline only)
# ---------------------------------------------------------------------------

_RULES_YAML = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "full_rules85.yaml"
_BBS_YAML = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "shared_bbs.yaml"


def _rules():
    return parse_rules_file(_RULES_YAML).rules


def _shared_bbs():
    return load_shared_bbs(_BBS_YAML)


# TL-2026-1693-style threat: flat bundle (the shape ``build_summary`` and the
# live pipeline normalizer consume). Subset of the acceptance 45-TTP bundle.
_THREAT_BUNDLE = {
    "id": "TL-2026-1693",
    "title": "Sauri",
    "sectors": ["finance", "cryptocurrency"],
    "regions": ["Global"],
    "ttps": [
        "T1027", "T1003.002", "T1078", "T1204",
        "T1102", "T1041", "T1486", "T1496",
    ],
    "iocs": [],
    "actor_confidence": "high",
}


def _build(tenant_id: str = "finance", **kwargs):
    return build_summary(
        threat_id="TL-2026-1693",
        bundle=_THREAT_BUNDLE,
        tenant=require_tenant(tenant_id),
        rules=_rules(),
        shared_bbs=_shared_bbs(),
        **kwargs,
    )


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
def test_bluf_is_russian_and_carries_threat_identity():
    sm = _build("finance")

    assert sm.threat_id == "TL-2026-1693"
    assert sm.zone in {"green", "amber", "red"}
    assert "Сводка" in sm.bluf_ru
    assert "TL-2026-1693" in sm.bluf_ru
    # Bottom line mentions coverage ratio and the top hypothesis.
    assert "Покрытие" in sm.bluf_ru
    assert "Топ-гипотеза" in sm.bluf_ru


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
def test_hypotheses_are_priority_sorted_top_blind_spots():
    sm = _build("finance", max_hypotheses=3)
    assert 1 <= len(sm.hypotheses) <= 3

    priorities = [h.priority for h in sm.hypotheses]
    assert priorities == sorted(priorities, reverse=True)

    # Seeded from blind spots: a gap hypothesis must carry the genau marker.
    gap = [h for h in sm.hypotheses if h.coverage_status == "COVERAGE_GAP"]
    assert gap, "expected at least one coverage-gap hypothesis among the top blind spots"
    assert all(h.gap_marker_ru == GAP_MARKER_RU for h in gap)


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="RULES fixture not present")
def test_covered_hypothesis_carries_rules_and_copy_ready_aql():
    sm = _build("finance", max_hypotheses=10)
    covered = [h for h in sm.hypotheses if h.covering_rule_ids]
    assert covered, "no covered hypothesis among the top blind spots"

    for h in covered:
        assert h.covering_rule_ids
        assert h.copy_ready_aql is not None
        bundle = h.copy_ready_aql
        assert bundle.aql.startswith("SELECT * FROM events WHERE")
        assert isinstance(bundle.copy_ready, bool)
        assert bundle.log_source


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="RULES fixture not present")
def test_hypothesis_carries_admiralty_and_flags():
    sm = _build("finance", max_hypotheses=5)
    for h in sm.hypotheses:
        assert h.admiralty.letter in {"B", "C", "D"}
        assert h.admiralty.digit in {"2", "3", "4", "5"}
        assert h.admiralty.rationale_ru
        assert h.text_ru
        assert isinstance(h.is_chokepoint, bool)
        assert isinstance(h.secondary_blind_flags, list)
        # Russian rendering pipeline stays glossary-faithful.
        assert h.coverage_status_ru


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="RULES fixture not present")
def test_determinism_identical_bytes_across_runs():
    first = _build("finance").model_dump()
    second = _build("finance").model_dump()
    assert first == second


def test_summary_seam_default_tenant_offline():
    """The orchestration seam with an explicit bundle skips the live fetch."""
    asyncio.run(
        summary(
            threat_id="TL-2026-1693",
            bundle=_THREAT_BUNDLE,
            rules=_rules(),
            shared_bbs=_shared_bbs(),
            max_hypotheses=2,
        )
    )


# ---------------------------------------------------------------------------
# M6.4 enrichment: management summary HypothesisOut echoes the hunt context
# ---------------------------------------------------------------------------


def test_summary_hypothesis_carries_technique_context():
    sm = _build("finance", max_hypotheses=5)
    for h in sm.hypotheses:
        # technique_name and tactic resolved deterministically.
        assert isinstance(h.technique_name, str)
        assert h.tactic, f"missing tactic for {h.technique_id}"
        assert h.expected_evidence_ru
        # Candidate chokepoints present (durable semantic fields).
        assert isinstance(h.candidate_chokepoints, list)
        assert isinstance(h.iocs, list)
        assert h.threat_title == "Sauri"
        assert h.data_sources


def test_summary_determinism_includes_enrichment():
    first = _build("finance").model_dump()
    second = _build("finance").model_dump()
    assert first == second