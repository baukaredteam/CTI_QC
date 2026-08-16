"""M6.4 — persistent Hypothesis data model.

A single falsifiable hunt hypothesis produced by the feed scanner from a
threat bundle and a tenant. Unlike the M6.3 read-only ``HypothesisOut``
(summary), this is the stored record: it carries a status lifecycle
(``proposed`` → ``validated`` | ``rejected``), provenance (threat + tenant),
an Admiralty code, expected-evidence notes, and chokepoint fields with LOW
adversary control. The in-memory + JSON-file store lives in
``app.services.hypothesis_store``; M5 swaps that seam for PostgreSQL rows.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.management import AdmiraltyOut


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


class Hypothesis(BaseModel):
    """Stored hunt hypothesis record produced by the feed scanner."""

    id: str = Field(description="Stable store key (uid)")
    threat_id: str
    tenant_id: str
    technique_id: str
    technique_name: str = Field(default="", description="ATT&CK technique name")
    tactic: str = ""
    priority: float = 0.0
    zone: str = ""
    status: str = "proposed"  # proposed | validated | rejected
    coverage_status: str = ""
    coverage_status_ru: str = ""
    covering_rule_ids: list[str] = Field(default_factory=list)
    admiralty: AdmiraltyOut
    chokepoints: list[HypothesisChokepoint] = Field(default_factory=list)
    candidate_chokepoints: list[HypothesisChokepoint] = Field(default_factory=list)
    expected_evidence_ru: str = Field(
        default="", description="Russian statement of what evidence to look for"
    )
    text_ru: str = Field(default="", description="One-paragraph Russian hypothesis")
    threat_title: str = Field(default="", description="Threat bundle title")
    threat_summary: str = Field(default="", description="Short Russian threat summary")
    actor: str = Field(default="", description="Attributed threat actor (or empty)")
    sectors: list[str] = Field(default_factory=list, description="Targeted sectors")
    iocs: list[HypothesisIOC] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    # Ticket 04 (R2-Q3): display-only bonus = priority × 1.25 for high actor
    # confidence. Never mutates priority, never reorders the M6.1 queue.
    confidence_priority_bonus: float | None = Field(default=None)
    # Ticket 08 (M6.4): enrichment fields filled by threadlinqs_mcp_enricher
    # from get_threat_hunting_bundle; empty until that seam runs.
    related_threats: list[str] = Field(default_factory=list)
    adversary_playbooks: list[str] = Field(default_factory=list)
    infrastructure_pivots: list[dict] = Field(default_factory=list)