"""Admiralty source-evaluation module — M6.3, ticket 01. Pure logic, no I/O.

Computes a deterministic NATO-style Admiralty code per hunt hypothesis.
See ADR-0002 for the locked mapping; the LLM never participates in the
letter/digit (it only wraps the computed code in Russian prose later).

- Letter from source structure:
    B — structured Threadlinqs bundle (indicators + MITRE present)
    C — narrative-only / single-source extraction
    D — template-derived or uncorroborated
- Digit from corroboration:
    2 — two or more strong signals
    3 — one strong signal
    4 — no strong signal (weak/partial corroboration)
    5 — coverage is a COVERAGE_GAP (speculative; nothing corroborates)

Letters A and digits 1/6 are intentionally unreachable from one bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.services.coverage.analyzer import COVERAGE_GAP

# Corroboration floor: an IOC block must yield at least this many IOCs to
# count as one strong corroboration signal.
IOC_STRONG_THRESHOLD = 2


class SourceStructure(Enum):
    """How the underlying threat source is structured."""

    STRUCTURED = "structured"            # indicators + MITRE present
    NARRATIVE_ONLY = "narrative_only"    # narrative / single-source extraction
    TEMPLATE_DERIVED = "template_derived"


_LETTER_BY_SOURCE: dict[SourceStructure, str] = {
    SourceStructure.STRUCTURED: "B",
    SourceStructure.NARRATIVE_ONLY: "C",
    SourceStructure.TEMPLATE_DERIVED: "D",
}


@dataclass(frozen=True)
class CorroborationEvidence:
    """The corroboration facts the digit is derived from (ADR-0002).

    Only booleans/counts enter here — no raw bundle text, no LLM output.
    The caller (management service) derives these from the normalized threat
    and the coverage report.
    """

    ioc_count: int = 0
    actor_confidence_high: bool = False
    sufficiency_high: bool = False
    primary_status: str = "COVERED"


@dataclass(frozen=True)
class AdmiraltyCode:
    """Structured Admiralty evaluation for one hypothesis."""

    letter: str
    digit: str
    rationale_ru: str


def _count_strong_signals(evidence: CorroborationEvidence) -> int:
    """Number of independent corroboration signals above their thresholds."""
    strong = 0
    if evidence.ioc_count >= IOC_STRONG_THRESHOLD:
        strong += 1
    if evidence.actor_confidence_high:
        strong += 1
    if evidence.sufficiency_high:
        strong += 1
    return strong


def assign(source_structure: SourceStructure, evidence: CorroborationEvidence) -> AdmiraltyCode:
    """Deterministically compute the Admiralty code for a hypothesis.

    Args:
        source_structure: How the threat source is structured (letter input).
        evidence: Corroboration facts (digit input).

    Returns:
        AdmiraltyCode with letter (B/C/D), digit (2-5), and a Russian rationale.
    """
    letter = _LETTER_BY_SOURCE[source_structure]

    if evidence.primary_status == COVERAGE_GAP:
        digit = "5"
        digit_reason_ru = (
            "покрывающего правила нет — гипотеза спекулятивна, подтверждение отсутствует"
        )
    else:
        strong = _count_strong_signals(evidence)
        if strong >= 2:
            digit = "2"
            digit_reason_ru = "два и более независимых подтверждающих сигнала"
        elif strong == 1:
            digit = "3"
            digit_reason_ru = "один сильный подтверждающий сигнал"
        else:
            digit = "4"
            digit_reason_ru = "подтверждение слабое или частичное"

    letter_reason_ru = {
        "B": "структурированный набор данных угрозы (индикаторы и MITRE)",
        "C": "нарративный источник или извлечение из единственного источника",
        "D": "шаблонный вывод без независимого подтверждения",
    }[letter]

    return AdmiraltyCode(
        letter=letter,
        digit=digit,
        rationale_ru=f"{letter}-{digit}: {digit_reason_ru}; источник: {letter_reason_ru}",
    )
