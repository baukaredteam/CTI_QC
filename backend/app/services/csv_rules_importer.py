"""CSV → RulesFile importer (same schema as rules_parser).

The SOC export is the completeness source: delimiter ``;``, 346 rows /
345 unique ``INC_*`` names after dropping 1 duplicate. Cyrillic header
bytes are often corrupted; English column names (``Rule``, ``BB``,
``BB2``–``BB5``, ``SYSMON``) stay usable. The checked-in fixture is the
14-rule gold extract until that file is dropped in.

BB chain is taken from Rule / BB / BB2 / BB3 / BB4 / BB5. ``INC_*``
rule names are mapped to ``BB_*`` for shared-catalog lookup.
"""

from __future__ import annotations

import csv
import io
import logging
import re
from pathlib import Path
from typing import Any

from app.schemas.rules import BuildingBlock, Rule, RulesFile

logger = logging.getLogger(__name__)

_INC_RE = re.compile(r"(INC_\d+)", re.IGNORECASE)
_TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
_TRUE = frozenset({"1", "true", "yes", "y", "da", "да", "enabled", "sysmon", "x"})

# Verified SOC export layout when the header is unreadable.
_POSITIONAL = {
    "ID": 0,
    "Rules in Qradar": 1,
    "log source": 2,
    "enabled": 3,
    "created": 4,
    "modified": 5,
    "category": 6,
    "criticality": 7,
    "Rule": 8,
    "BB": 9,
    "BB2": 10,
    "BB3": 11,
    "BB4": 12,
    "BB5": 13,
    "SYSMON": 14,
}

_ALIASES = {
    "id": "ID",
    "rules in qradar": "Rules in Qradar",
    "log source": "log source",
    "logsource": "log source",
    "enabled": "enabled",
    "created": "created",
    "created_date": "created",
    "modified": "modified",
    "modified_date": "modified",
    "category": "category",
    "criticality": "criticality",
    "rule": "Rule",
    "bb": "BB",
    "bb2": "BB2",
    "bb3": "BB3",
    "bb4": "BB4",
    "bb5": "BB5",
    "sysmon": "SYSMON",
}

_CHAIN_KEYS = ("Rule", "BB", "BB2", "BB3", "BB4", "BB5")


def parse_rules_csv(path: str | Path) -> RulesFile:
    """Load a SOC-export CSV into the same RulesFile schema as YAML."""
    path = Path(path)
    text = _read_text(path)
    reader = csv.reader(io.StringIO(text), delimiter=";")
    try:
        header = next(reader)
    except StopIteration:
        return RulesFile(metadata={"source": "csv", "path": str(path), "unique_rules": 0})

    colmap = _column_map(header)
    rules: list[Rule] = []
    seen: set[str] = set()
    rows_seen = 0
    duplicates = 0
    skipped_empty = 0
    skipped_named = 0

    for raw_row in reader:
        if not raw_row or not any(c.strip() for c in raw_row):
            skipped_empty += 1
            continue
        rows_seen += 1
        row = list(raw_row)
        try:
            rule = _row_to_rule(row, colmap)
        except Exception:
            skipped_named += 1
            logger.exception("Failed to parse CSV row %d", rows_seen)
            continue
        if not rule.rule_id and not rule.rule_name:
            skipped_empty += 1
            continue
        key = rule.rule_id or rule.rule_name
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        rules.append(rule)

    return RulesFile(
        rules=rules,
        metadata={
            "source": "csv",
            "path": str(path),
            "rows_seen": rows_seen,
            "unique_rules": len(rules),
            "duplicates": duplicates,
            "skipped_empty": skipped_empty,
            "skipped_named": skipped_named,
        },
    )


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    preferred: str | None = None
    last = ""
    for enc in ("utf-8-sig", "utf-8", "cp1251", "cp1252", "latin-1"):
        try:
            text = data.decode(enc)
        except UnicodeDecodeError:
            continue
        last = text
        first = text.splitlines()[0] if text else ""
        if "Rule" in first and ("BB" in first or "SYSMON" in first):
            return text
        if preferred is None:
            preferred = text
    return preferred or last


def _column_map(header: list[str]) -> dict[str, int]:
    found: dict[str, int] = {}
    for i, raw in enumerate(header):
        key = _ALIASES.get(raw.strip().casefold())
        if key is not None:
            found[key] = i
    if "Rule" in found and "BB" in found:
        return found
    # Header unreadable — fall back to the verified SOC column order.
    if len(header) >= 15:
        return dict(_POSITIONAL)
    return found


def _cell(row: list[str], colmap: dict[str, int], key: str) -> str:
    idx = colmap.get(key)
    if idx is None or idx >= len(row):
        return ""
    return row[idx].strip()


def _as_bool(value: str) -> bool:
    return value.strip().casefold() in _TRUE


def _rule_name_to_bb_id(cell: str) -> str:
    cell = cell.strip()
    if cell[:4].upper() == "INC_":
        return "BB_" + cell[4:]
    return cell


def _extract_rule_id(rule_cell: str, id_cell: str) -> str:
    for src in (id_cell, rule_cell):
        match = _INC_RE.search(src)
        if match:
            return match.group(1).upper()
    return (rule_cell or id_cell).strip()


def _extract_rule_name(rule_cell: str, qradar_name: str) -> str:
    if ":" in rule_cell:
        return rule_cell.split(":", 1)[1].strip()
    return (qradar_name or rule_cell).strip()


def _mitre(category: str) -> list[str]:
    return [m.group(0).upper() for m in _TECH_RE.finditer(category)]


def _row_to_rule(row: list[str], colmap: dict[str, int]) -> Rule:
    rule_cell = _cell(row, colmap, "Rule")
    id_cell = _cell(row, colmap, "ID")
    qradar_name = _cell(row, colmap, "Rules in Qradar")
    category = _cell(row, colmap, "category")

    chain: list[str] = []
    for key in _CHAIN_KEYS:
        raw = _cell(row, colmap, key)
        if not raw:
            continue
        bb_id = _rule_name_to_bb_id(raw) if key == "Rule" else raw
        if bb_id and bb_id not in chain:
            chain.append(bb_id)

    building_blocks = [
        BuildingBlock(bb_id=bb_id, level=1, depends_on_bb=[])
        for bb_id in chain
    ]

    enabled_cell = _cell(row, colmap, "enabled")
    return Rule(
        rule_id=_extract_rule_id(rule_cell, id_cell),
        rule_name=_extract_rule_name(rule_cell, qradar_name),
        enabled=True if enabled_cell == "" else _as_bool(enabled_cell),
        created_date=_cell(row, colmap, "created"),
        modified_date=_cell(row, colmap, "modified"),
        log_source=_cell(row, colmap, "log source"),
        criticality=_cell(row, colmap, "criticality"),
        mitre_techniques=_mitre(category),
        sysmon_required=_as_bool(_cell(row, colmap, "SYSMON")),
        building_blocks=building_blocks,
    )


def csv_import_report(rf: RulesFile) -> dict[str, Any]:
    """Return the importer's row-count metadata (no silent skip without counts)."""
    meta = dict(rf.metadata or {})
    meta.setdefault("unique_rules", len(rf.rules))
    return meta
