"""Pydantic schemas for the AQL emitter (M4).

Defines the structured output of the regex guard and the AQL emitter:
- EmitterWarning: a single guard/emitter diagnostic.
- SufficiencyResult: how much of the rule's fields the emitted AQL can check.
- AQLRule: the final emitted rule with its warnings and sufficiency score.

This module is intentionally schema-only; it performs no detection or emission.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class EmitterWarning(BaseModel):
    """A single warning or block raised by the regex guard or AQL emitter.

    severity is either "block" (the rule cannot be emitted) or "warning"
    (the rule can be emitted but a condition is suspect).
    """

    code: str
    message: str
    severity: str = "warning"  # "block" or "warning"
    pattern: str = ""


class SufficiencyResult(BaseModel):
    """How completely the emitted AQL covers the rule's required fields."""

    sufficiency_pct: float
    fields_checked: list[str] = Field(default_factory=list)
    partial_fields: list[str] = Field(default_factory=list)
    blind_fields: list[str] = Field(default_factory=list)


class AQLRule(BaseModel):
    """The final emitted AQL rule plus its diagnostics."""

    rule_id: str
    log_source: str = ""
    aql: str = ""
    copy_ready: bool = False
    warnings: list[EmitterWarning] = Field(default_factory=list)
    sufficiency: SufficiencyResult | None = None