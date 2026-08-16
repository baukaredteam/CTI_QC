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

import pytest

from app.services.constants import INDEXED_FIELDS
from app.services.mitre_meta import (
    TECHNIQUE_NAMES,
    TTP_TACTICS,
    candidate_fields,
    evidence_fields,
    gap_expected_evidence_ru,
    low_control_fields,
    parse_fields_catalog,
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


# ---------------------------------------------------------------------------
# 4. parse_fields_catalog — canonical requires_gpo coercion (hardening)
#
# Raw fields.yaml values are untrusted QRadar data: a bare ``bool(...)``
# reads ``"false"`` as True, so unknown raw values must never be truthy.
# ---------------------------------------------------------------------------

_UNKNOWN = object()


def _gpo_entry(name: str, value=_UNKNOWN, control: str = "LOW") -> dict:
    """One raw fields.yaml custom_field row (untrusted QRadar shape).

    ``value`` is the raw ``requires_gpo`` payload; the _UNKNOWN sentinel
    omits the key entirely (distinct from an explicit ``None``).
    """
    row = {"name": name, "availability": "full", "adversary_control": control}
    if value is not _UNKNOWN:
        row["requires_gpo"] = value
    return row


def _parsed(rows: list[dict]) -> dict:
    return parse_fields_catalog({"custom_fields": rows})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # native bools preserved as-is
        (True, True),
        (False, False),
        # the bug: bool("false") is truthy — raw false tokens must be False
        ("false", False),
        ("FALSE", False),
        ("False", False),
        ("no", False),
        ("0", False),
        ("off", False),
        ("", False),
        ("   ", False),
        # missing / None -> default False
        (None, False),
        (_UNKNOWN, False),
        # strip + case-insensitive true tokens
        (" true ", True),
        ("TRUE", True),
        ("True", True),
        ("yes", True),
        ("YES", True),
        ("1", True),
        ("on", True),
        ("ON", True),
        # unknown raw values -> safe False, never truthy
        ("maybe", False),
        ("TRUE!", False),
        ("2", False),
    ],
)
def test_requires_gpo_raw_value_coerced_by_explicit_token_policy(raw, expected):
    catalog = _parsed([_gpo_entry("gpo_probe", raw)])
    assert catalog["gpo_probe"]["requires_gpo"] is expected


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("false", "true", True),
        ("true", "false", True),
        # red before the fix: bool("false") OR bool("false") is True
        ("false", "false", False),
        (" ", "1", True),
        (None, "off", False),
        (_UNKNOWN, "on", True),
        (True, "false", True),
        (False, False, False),
    ],
)
def test_requires_gpo_duplicate_merge_still_or_after_canonical_coercion(
    first, second, expected
):
    catalog = _parsed([
        _gpo_entry("dup_gpo", first),
        _gpo_entry("dup_gpo", second),
    ])
    assert catalog["dup_gpo"]["requires_gpo"] is expected


def test_low_plus_low_duplicate_stays_candidate_after_gpo_fix():
    # The GPO coercion change must not perturb the exact-LOW intersection.
    catalog = _parsed([
        _gpo_entry("dup_low", "false"),
        _gpo_entry("dup_low", "true"),
    ])
    assert "dup_low" in low_control_fields(catalog)


def test_low_plus_high_duplicate_stays_excluded_after_gpo_fix():
    catalog = _parsed([
        _gpo_entry("dup_conflict", "true", control="LOW"),
        _gpo_entry("dup_conflict", "false", control="HIGH"),
    ])
    assert "dup_conflict" not in low_control_fields(catalog)
    # merge still ORs the coerced flags across the duplicate entries
    assert catalog["dup_conflict"]["requires_gpo"] is True


def test_parse_fields_catalog_is_deterministic_across_repeated_calls():
    raw = {
        "custom_fields": [
            _gpo_entry("a", "false"),
            _gpo_entry("b", " True "),
            _gpo_entry("c"),
            _gpo_entry("d", None),
            _gpo_entry("e", "maybe"),
        ]
    }
    assert parse_fields_catalog(raw) == parse_fields_catalog(raw)