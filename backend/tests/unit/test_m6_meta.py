"""M6.4 meta test suite — shared MITRE metadata + telemetry templates.

The generator and the management summary both fill technique-level context
(technique name, tactic, expected evidence, candidate chokepoint fields) from
one deterministic, offline module: ``app.services.mitre_meta``. The module
owns:

1. ``TTP_TACTICS`` — technique → tactic (moved from the old test-local map so
   the acceptance test and the live scan share one source).
2. ``TECHNIQUE_NAMES`` — technique → ATT&CK name (best-effort facts, never
   invented; empty when unknown).
3. Per-technique telemetry templates: expected-evidence and candidate
   chokepoint *fields* drawn from the real field catalog (INDEXED_FIELDS and
   the durable LOW-adversary-control fields of ``fixtures/fields.yaml``).

All lookups are deterministic pure functions (no network, no LLM).
"""

from __future__ import annotations

from app.services.constants import INDEXED_FIELDS
from app.services.mitre_meta import (
    TECHNIQUE_NAMES,
    TTP_TACTICS,
    candidate_fields,
    evidence_fields,
    gap_expected_evidence_ru,
    technique_meta,
)


# ---------------------------------------------------------------------------
# 1. tactic map
# ---------------------------------------------------------------------------


def test_tactic_map_covers_the_acceptance_bundle():
    # Same keys the M6.1 acceptance fixture relies on — but now shared.
    assert TTP_TACTICS["T1566.001"] == "initial-access"
    assert TTP_TACTICS["T1204"] == "execution"
    assert TTP_TACTICS["T1003.002"] == "credential-access"
    assert TTP_TACTICS["T1082"] == "discovery"
    assert TTP_TACTICS["T1543.003"] == "persistence"
    assert TTP_TACTICS["T1573.001"] == "command-and-control"
    assert TTP_TACTICS["T1041"] == "exfiltration"
    assert TTP_TACTICS["T1486"] == "impact"
    assert len(TTP_TACTICS) >= 40


def test_unknown_technique_has_no_tactic():
    assert technique_meta("T9988").tactic == ""


# ---------------------------------------------------------------------------
# 2. technique names
# ---------------------------------------------------------------------------


def test_known_technique_has_a_name():
    assert technique_meta("T1059.001").name == "PowerShell"
    assert technique_meta("T1082").name


def test_missing_name_falls_back_to_empty_string():
    assert technique_meta("T1234").name == ""


def test_names_extend_the_tactic_map():
    # Every known ATT&CK name must also have a tactic (coherent table), and
    # the tactic table may hold extra techniques without a curated name.
    for tid in TECHNIQUE_NAMES:
        assert tid in TTP_TACTICS, tid


# ---------------------------------------------------------------------------
# 3. evidence + candidate field templates
# ---------------------------------------------------------------------------


def test_evidence_fields_grounded_in_real_catalog():
    fields = evidence_fields("T1059.001")
    assert isinstance(fields, (tuple, list))
    assert fields
    # Real QRadar indexing columns are always part of an evidence template.
    assert "qid" in fields and "eventid" in fields and len(fields) >= 3


def test_candidate_fields_are_durable_semantic_fields():
    cand = candidate_fields("T1059.001")
    assert isinstance(cand, tuple)
    assert cand
    # Candidates are attacker-influenced semantic fields, never the index keys.
    for field in cand:
        assert field not in INDEXED_FIELDS


def test_gap_evidence_text_is_deterministic_and_named():
    first = gap_expected_evidence_ru("T1059.001")
    second = gap_expected_evidence_ru("T1059.001")
    assert first == second
    assert "T1059.001" in first