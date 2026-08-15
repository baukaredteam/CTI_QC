"""M6.3 ticket 01 — Admiralty deterministic module.

Covers the ADR-0002 mapping:
- Letter from source structure:
    B — structured Threadlinqs bundle (indicators + MITRE present)
    C — narrative-only / single-source extraction
    D — template-derived or uncorroborated
- Digit from corroboration:
    2 — two or more strong signals
    3 — one strong signal
    4 — no strong signal (weak/partial)
    5 — coverage is a COVERAGE_GAP (speculative, nothing corroborates)

Asserts external behavior only: the structured {letter, digit, rationale_ru}
output and the determinism guarantee. No LLM anywhere.
"""

from __future__ import annotations

import pytest

from app.services.admiralty import (  # type: ignore[import-not-found]  # noqa: F401
    AdmiraltyCode,
    CorroborationEvidence,
    SourceStructure,
    assign,
)


def _evidence(**kw):
    defaults = {
        "ioc_count": 0,
        "actor_confidence_high": False,
        "sufficiency_high": False,
        "primary_status": "COVERED",
    }
    defaults.update(kw)
    return CorroborationEvidence(**defaults)


# ── Letter: source structure → B/C/D ─────────────────────────────────────────


def test_letter_structured_bundle_is_b():
    assert assign(SourceStructure.STRUCTURED, _evidence()).letter == "B"


def test_letter_narrative_only_is_c():
    assert assign(SourceStructure.NARRATIVE_ONLY, _evidence()).letter == "C"


def test_letter_template_derived_is_d():
    assert assign(SourceStructure.TEMPLATE_DERIVED, _evidence()).letter == "D"


# ── Digit: corroboration signals per ADR-0002 ────────────────────────────────


def test_digit_two_or_more_strong_signals():
    ev = _evidence(
        ioc_count=3,           # above threshold
        actor_confidence_high=True,
        sufficiency_high=False,
    )
    assert assign(SourceStructure.STRUCTURED, ev).digit == "2"


def test_digit_exactly_two_signals_is_two():
    ev = _evidence(
        ioc_count=2,
        actor_confidence_high=True,
        sufficiency_high=False,
    )
    assert assign(SourceStructure.STRUCTURED, ev).digit == "2"


def test_digit_one_strong_signal_is_three():
    ev = _evidence(ioc_count=5, actor_confidence_high=False, sufficiency_high=False)
    assert assign(SourceStructure.STRUCTURED, ev).digit == "3"


def test_digit_no_strong_signal_is_four():
    ev = _evidence(ioc_count=0, actor_confidence_high=False, sufficiency_high=False)
    assert assign(SourceStructure.STRUCTURED, ev).digit == "4"


def test_digit_coverage_gap_is_five_even_with_signals():
    ev = _evidence(
        ioc_count=9,
        actor_confidence_high=True,
        sufficiency_high=True,
        primary_status="COVERAGE_GAP",
    )
    assert assign(SourceStructure.STRUCTURED, ev).digit == "5"


# ── Output shape / determinism / language ────────────────────────────────────


def test_output_shape():
    code = assign(SourceStructure.STRUCTURED, _evidence())
    assert isinstance(code, AdmiraltyCode)
    assert isinstance(code.letter, str)
    assert isinstance(code.digit, str)
    assert code.letter in {"B", "C", "D"}
    assert code.digit in {"2", "3", "4", "5"}


def test_deterministic_for_same_input():
    ev = _evidence(ioc_count=4, actor_confidence_high=True, sufficiency_high=True)
    left = assign(SourceStructure.STRUCTURED, ev)
    right = assign(SourceStructure.STRUCTURED, ev)
    assert left == right
    assert left.letter == right.letter
    assert left.digit == right.digit
    assert left.rationale_ru == right.rationale_ru


def test_rationale_is_russian():
    # Any repeated code across source structures must read like Cyrillic prose.
    texts = [
        assign(structure, _evidence()).rationale_ru
        for structure in (SourceStructure.STRUCTURED, SourceStructure.NARRATIVE_ONLY, SourceStructure.TEMPLATE_DERIVED)
    ]
    for text in texts:
        assert text
        assert any("\u0400" <= char <= "\u04FF" for char in text)