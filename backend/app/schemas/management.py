"""M6.3, ticket 04 — management summary schemas.

Serializable shapes for the backdrop/management_service and the future
/management route (ticket 05). The summary is deterministic and offline-first:
Russian BLUF, priority-sorted hunt hypotheses, per-hypothesis Admiralty code,
coverage status + rules, chokepoint/secondary flags, and the copy-ready AQL
bundle (None for a COVERAGE_GAP — analysed analyst authors a new rule).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.aql import AQLRule


class AdmiraltyOut(BaseModel):
    """Structured Admiralty evaluation carried by one hunt hypothesis."""

    letter: str = Field(description="Source-structure letter (B/C/D)")
    digit: str = Field(description="Credibility digit (2..5)")
    rationale_ru: str = Field(description="Russian rationale for the code")


class HypothesisChokepoint(BaseModel):
    """One attacker-nuisance field with LOW adversary control (a durability
    disadvantage the defender can turn into a detection advantage)."""

    field: str = Field(description="Source field name")
    note_ru: str = Field(description="Russian durability/collection note")


class HypothesisIOC(BaseModel):
    """A blockable indicator attached to the hypothesis for hunt grounding."""

    ioc_type: str = Field(description="Canonical IOC type (domain/ipv4/hash…)")
    value: str = Field(description="Indicator value")
    note_ru: str = Field(default="", description="Russian verdict/context note")


class HypothesisOut(BaseModel):
    """One hunt hypothesis: a high-priority blind spot + its verdicts."""

    technique_id: str
    technique_name: str = Field(
        default="", description="ATT&CK technique name (best-effort, empty when unknown)"
    )
    tactic: str = ""
    priority: float = 0.0
    coverage_status: str
    coverage_status_ru: str
    covering_rule_ids: list[str] = Field(default_factory=list)
    # Emitted AQL for the covering rule (None when nothing covers the behavior).
    copy_ready_aql: AQLRule | None = None
    secondary_blind_flags: list[str] = Field(default_factory=list)
    is_chokepoint: bool = False
    admiralty: AdmiraltyOut
    # Set to the exact gap marker when coverage_status == COVERAGE_GAP.
    gap_marker_ru: str | None = None
    text_ru: str = Field(description="One-paragraph Russian hypothesis prose")
    expected_evidence_ru: str = Field(
        default="", description="Russian statement of what evidence to look for"
    )
    candidate_chokepoints: list[HypothesisChokepoint] = Field(default_factory=list)
    iocs: list[HypothesisIOC] = Field(
        default_factory=list, description="Top blockable indicators for the hunt"
    )
    threat_title: str = Field(default="", description="Threat bundle title")
    threat_summary: str = Field(default="", description="Short Russian threat summary")
    actor: str = Field(default="", description="Attributed threat actor (or empty)")
    sectors: list[str] = Field(default_factory=list, description="Targeted sectors")
    data_sources: list[str] = Field(default_factory=list)


class ManagementSummary(BaseModel):
    """The «Сводка и гипотезы» response body (M6.3)."""

    threat_id: str
    title: str
    actor: str = ""
    tenant_id: str
    tenant_name: str = ""
    score: float = 0.0
    zone: str = ""
    status_counts: dict[str, int] = Field(default_factory=dict)
    tactic_coverage: dict[str, float] = Field(default_factory=dict)
    bluf_ru: str = Field(description="Russian BLUF («Сводка») summary line")
    hypotheses: list[HypothesisOut] = Field(default_factory=list)