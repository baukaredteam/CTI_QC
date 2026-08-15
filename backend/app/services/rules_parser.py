"""YAML-based QRadar rules parser.

M2 — rules_parser.py

Loads a rules YAML file, strips all string values (trailing/leading whitespace),
and returns validated Pydantic models.  Does NOT validate regex syntax in
conditions — that is deferred to the AQL emitter (M4).

Only the ``rules`` key is parsed into Rule objects.  ``metadata`` and
``fixes_applied`` are preserved as raw dicts/strings for informational use
but are never turned into rules.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from app.schemas.rules import (
    BuildingBlock,
    CustomField,
    FieldsFile,
    Rule,
    RulesFile,
)
from app.services.constants import strip_yaml_values

logger = logging.getLogger(__name__)


def parse_rules_file(path: str | Path) -> RulesFile:
    """Load and parse a rules YAML file.

    Parameters
    ----------
    path:
        Filesystem path to the YAML file (e.g. ``fixtures/full_rules85.yaml``).

    Returns
    -------
    RulesFile
        Validated model with ``rules``, ``metadata``, and ``fixes_applied``.
        Only entries under the ``rules`` key become Rule objects.
    """
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        logger.warning("Rules file %s did not parse as a dict", path)
        return RulesFile()

    cleaned = strip_yaml_values(raw)

    # Extract the three top-level keys
    raw_rules = cleaned.get("rules", [])
    metadata = cleaned.get("metadata", {})
    fixes = cleaned.get("fixes_applied", "")

    if not isinstance(raw_rules, list):
        logger.warning("'rules' key in %s is not a list", path)
        raw_rules = []

    rules: list[Rule] = []
    for i, entry in enumerate(raw_rules):
        if not isinstance(entry, dict):
            logger.warning("Rule entry %d in %s is not a dict, skipping", i, path)
            continue
        try:
            rule = _parse_single_rule(entry)
            rules.append(rule)
        except Exception:
            rid = entry.get("rule_id", "unknown")
            logger.exception("Failed to parse rule %s at index %d", rid, i)

    return RulesFile(
        rules=rules,
        metadata=metadata if isinstance(metadata, dict) else {},
        fixes_applied=fixes if isinstance(fixes, str) else str(fixes),
    )


def _parse_single_rule(data: dict[str, Any]) -> Rule:
    """Parse a single rule dict into a Rule model."""
    # Parse building blocks
    bbs: list[BuildingBlock] = []
    for bb_data in (data.get("building_blocks") or []):
        if isinstance(bb_data, dict):
            bbs.append(BuildingBlock(**bb_data))

    # Parse custom fields
    fields: list[CustomField] = []
    for cf_data in (data.get("custom_fields") or []):
        if isinstance(cf_data, dict):
            fields.append(CustomField(**cf_data))

    # Parse reference_sets_used — may be list of strings or list of dicts
    ref_sets = data.get("reference_sets_used") or []
    if isinstance(ref_sets, list):
        ref_sets = [str(r) for r in ref_sets]

    return Rule(
        rule_id=data.get("rule_id", ""),
        rule_name=data.get("rule_name", ""),
        enabled=data.get("enabled", True),
        created_date=data.get("created_date", ""),
        modified_date=data.get("modified_date", ""),
        event_count_30d=data.get("event_count_30d", 0),
        offense_count_30d=data.get("offense_count_30d", 0),
        log_source=data.get("log_source", ""),
        criticality=data.get("criticality", ""),
        mitre_techniques=data.get("mitre_techniques") or [],
        sysmon_required=data.get("sysmon_required", False),
        full_rule_logic=data.get("full_rule_logic", ""),
        building_blocks=bbs,
        effective_detection_logic=data.get("effective_detection_logic", ""),
        bb_chain_summary=data.get("bb_chain_summary", ""),
        custom_fields=fields,
        reference_sets_used=ref_sets,
    )


def parse_fields_file(path: str | Path) -> FieldsFile:
    """Load and parse a fields YAML file (fields.yaml).

    Parameters
    ----------
    path:
        Filesystem path to the YAML file.

    Returns
    -------
    FieldsFile
        Validated model with ``metadata`` and ``custom_fields``.
    """
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        logger.warning("Fields file %s did not parse as a dict", path)
        return FieldsFile()

    cleaned = strip_yaml_values(raw)

    metadata = cleaned.get("metadata", {})
    raw_fields = cleaned.get("custom_fields", [])

    if not isinstance(raw_fields, list):
        logger.warning("'custom_fields' key in %s is not a list", path)
        raw_fields = []

    fields: list[CustomField] = []
    for i, entry in enumerate(raw_fields):
        if not isinstance(entry, dict):
            logger.warning("Field entry %d in %s is not a dict, skipping", i, path)
            continue
        try:
            fields.append(CustomField(**entry))
        except Exception:
            name = entry.get("name", "unknown")
            logger.exception("Failed to parse field %s at index %d", name, i)

    return FieldsFile(
        metadata=metadata if isinstance(metadata, dict) else {},
        custom_fields=fields,
    )


def print_rules_summary(rf: RulesFile) -> None:
    """Print a human-readable summary of a parsed rules file."""
    rules = rf.rules
    sysmon_true = sum(1 for r in rules if r.sysmon_required)
    sysmon_false = len(rules) - sysmon_true

    # Count rules with cmdline custom field having availability=partial
    cmdline_partial = 0
    for r in rules:
        for cf in r.custom_fields:
            if cf.name == "cmdline" and cf.availability == "partial":
                cmdline_partial += 1
                break

    # Collect all unique custom field names
    all_fields: set[str] = set()
    for r in rules:
        for cf in r.custom_fields:
            all_fields.add(cf.name)

    # Collect all MITRE technique IDs
    all_mitre: set[str] = set()
    for r in rules:
        for t in r.mitre_techniques:
            all_mitre.add(t)

    print("=== Rules File Summary ===")
    print("  Total rules parsed    : %d" % len(rules))
    print("  sysmon_required=true  : %d" % sysmon_true)
    print("  sysmon_required=false : %d" % sysmon_false)
    print("  cmdline partial rules : %d" % cmdline_partial)
    print("  Unique custom fields  : %d — %s" % (len(all_fields), sorted(all_fields)))
    print("  Unique MITRE IDs      : %d — %s" % (len(all_mitre), sorted(all_mitre)))
    if rf.metadata:
        print("  Metadata              : %s" % rf.metadata)
    rule_ids = [r.rule_id for r in rules]
    print("  Rule IDs              : %s" % rule_ids)
    print("=" * 40)
