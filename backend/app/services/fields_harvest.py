"""Field harvester — extract custom field names from parsed rules.

M2 — fields_harvest.py

Collects every custom field referenced in parsed rules, annotates each with
availability and adversary_control from the rule context, and flags which
fields are QRadar system-indexed (fast-path for AQL generation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from app.schemas.rules import FieldsFile, Rule, RulesFile
from app.services.constants import INDEXED_FIELDS, SEMANTIC_FILTER_FIELDS


@dataclass
class HarvestedField:
    """A custom field with metadata aggregated across all rules that use it."""

    name: str
    is_indexed: bool = False
    is_semantic_filter: bool = False
    availabilities: set[str] = field(default_factory=set)
    adversary_controls: set[str] = field(default_factory=set)
    used_in_rules: list[str] = field(default_factory=list)


def harvest_fields_from_rules(rf: RulesFile) -> dict[str, HarvestedField]:
    """Walk all rules and collect unique custom fields with metadata.

    Returns a dict keyed by field name (lowercased).
    """
    result: dict[str, HarvestedField] = {}

    for rule in rf.rules:
        for cf in rule.custom_fields:
            key = cf.name.lower()
            if key not in result:
                result[key] = HarvestedField(
                    name=cf.name,
                    is_indexed=(key in INDEXED_FIELDS),
                    is_semantic_filter=(key in SEMANTIC_FILTER_FIELDS),
                )
            hf = result[key]
            if cf.availability:
                hf.availabilities.add(cf.availability.lower())
            if cf.adversary_control:
                hf.adversary_controls.add(cf.adversary_control.upper())
            if rule.rule_id not in hf.used_in_rules:
                hf.used_in_rules.append(rule.rule_id)

    return result


def harvest_fields_from_fields_file(ff: FieldsFile) -> dict[str, HarvestedField]:
    """Walk a fields YAML (fields.yaml) and collect unique custom fields.

    Returns a dict keyed by field name (lowercased).
    """
    result: dict[str, HarvestedField] = {}

    for cf in ff.custom_fields:
        key = cf.name.lower()
        if key not in result:
            result[key] = HarvestedField(
                name=cf.name,
                is_indexed=(key in INDEXED_FIELDS),
                is_semantic_filter=(key in SEMANTIC_FILTER_FIELDS),
            )
        hf = result[key]
        if cf.availability:
            hf.availabilities.add(cf.availability.lower())
        if cf.adversary_control:
            hf.adversary_controls.add(cf.adversary_control.upper())

    return result


def merge_harvests(
    *harvests: dict[str, HarvestedField],
) -> dict[str, HarvestedField]:
    """Merge multiple harvest results into one, combining metadata."""
    merged: dict[str, HarvestedField] = {}

    for harvest in harvests:
        for key, hf in harvest.items():
            if key not in merged:
                merged[key] = HarvestedField(
                    name=hf.name,
                    is_indexed=hf.is_indexed,
                    is_semantic_filter=hf.is_semantic_filter,
                )
            m = merged[key]
            m.availabilities.update(hf.availabilities)
            m.adversary_controls.update(hf.adversary_controls)
            for rid in hf.used_in_rules:
                if rid not in m.used_in_rules:
                    m.used_in_rules.append(rid)

    return merged


def get_partial_fields(harvest: dict[str, HarvestedField]) -> list[str]:
    """Return field names that have availability=partial in any rule."""
    return sorted(
        name for name, hf in harvest.items()
        if "partial" in hf.availabilities
    )


def get_high_adversary_fields(harvest: dict[str, HarvestedField]) -> list[str]:
    """Return field names with HIGH adversary control in any rule."""
    return sorted(
        name for name, hf in harvest.items()
        if "HIGH" in hf.adversary_controls
    )
