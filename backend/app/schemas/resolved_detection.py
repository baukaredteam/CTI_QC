"""Pydantic models for resolved detection logic after BB chain walking.

M3 — schemas/resolved_detection.py
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ResolutionWarning(BaseModel):
    """A non-fatal warning emitted during BB resolution."""

    warning_type: str          # "missing_building_block" | "corrupted_id_normalized"
    bb_id: str                 # the dangling or corrupted BB id
    rule_id: str = ""          # rule that triggered the warning
    message: str = ""


class ResolvedDetection(BaseModel):
    """The result of resolving a rule's building-block chain.

    Holds the merged conditions from the recursive BB walk, the flat
    list of custom field names referenced, the log source, and metadata
    about how the logic was derived.
    """

    rule_id: str
    rule_name: str = ""

    # Merged condition fragments collected during BB chain walk,
    # in order from leaf (log source) to root (rule-level BB).
    merged_conditions: list[str] = Field(default_factory=list)

    # How the logic was derived:
    #   "bb_chain"           — built from own_conditions of BBs
    #   "effective_fallback" — fell back to rule's effective_detection_logic
    logic_source: str = "bb_chain"

    # The terminal log source (e.g. "Microsoft Windows Security Event Log")
    log_source: str = ""

    # Flat list of custom field names referenced in conditions
    referenced_fields: list[str] = Field(default_factory=list)

    # BB IDs visited during resolution (for debugging)
    bb_chain: list[str] = Field(default_factory=list)

    # Non-fatal warnings (missing BBs, corrupted ids normalized, etc.)
    warnings: list[ResolutionWarning] = Field(default_factory=list)


class ResolutionError(Exception):
    """Raised on fatal resolution errors such as circular dependencies."""

    def __init__(self, message: str, cycle_path: list[str] | None = None):
        self.cycle_path = cycle_path or []
        super().__init__(message)
