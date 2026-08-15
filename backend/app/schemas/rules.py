"""Pydantic models for QRadar detection rules, building blocks, and custom fields.

M2 — schemas/rules.py

These models are intentionally lenient: string fields accept whatever the YAML
provides (after strip) and do NOT validate regex syntax.  Regex validation is
deferred to M4 (AQL emitter) so that the parser never silently drops rules.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CustomField(BaseModel):
    """A custom QRadar field referenced in a rule's conditions."""

    name: str
    internal_name: str = ""
    display_name: str = ""
    data_type: str = ""
    event_id_context: str = ""
    availability: str = ""          # "full" | "partial"
    adversary_control: str = ""     # "LOW" | "MED" | "HIGH"
    log_sources: list[str] = Field(default_factory=list)
    used_in_events: list[str] = Field(default_factory=list)
    notes: str = ""


class BuildingBlock(BaseModel):
    """An inline building-block definition embedded inside a rule."""

    bb_id: str
    bb_name: str = ""
    level: int = 0
    category: str = ""
    depends_on_bb: list[str] = Field(default_factory=list)
    own_conditions: str = ""        # raw condition text, not validated
    full_bb_logic: str = ""         # reference text, kept as-is
    sysmon_required: bool = False
    notes: str = ""


class ReferenceSet(BaseModel):
    """A QRadar reference set used by a rule."""

    rs_id: str = ""
    rs_name: str = ""
    type: str = ""
    case_sensitive: bool = True
    usage: str = ""


class Rule(BaseModel):
    """A single parsed QRadar detection rule."""

    rule_id: str
    rule_name: str = ""
    enabled: bool = True
    created_date: str = ""
    modified_date: str = ""
    event_count_30d: int = 0
    offense_count_30d: int = 0
    log_source: str = ""
    criticality: str = ""           # "Low" | "Medium" | "High"
    mitre_techniques: list[str] = Field(default_factory=list)
    sysmon_required: bool = False

    full_rule_logic: str = ""       # raw rule logic text, kept as-is
    building_blocks: list[BuildingBlock] = Field(default_factory=list)
    effective_detection_logic: str = ""
    bb_chain_summary: str = ""

    custom_fields: list[CustomField] = Field(default_factory=list)
    reference_sets_used: list[str] = Field(default_factory=list)


class RulesFile(BaseModel):
    """Top-level model for a parsed rules YAML file.

    Only the ``rules`` key is consumed; ``metadata`` and ``fixes_applied``
    are stored verbatim but not turned into Rule objects.
    """

    rules: list[Rule] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    fixes_applied: str = ""


class FieldsFile(BaseModel):
    """Top-level model for a parsed fields YAML file (fields.yaml)."""

    metadata: dict = Field(default_factory=dict)
    custom_fields: list[CustomField] = Field(default_factory=list)
