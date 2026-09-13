"""Building-block resolver — recursive BB chain walker.

M3 — bb_resolver.py

Builds a combined lookup of building blocks (inline from the rule, overlaid
with shared_bbs.yaml), then recursively walks depends_on_bb to merge
own_conditions along the chain.

Key design decisions:
- Inline BBs (from the rule) take priority over shared BBs.
- BB IDs are normalized by stripping all whitespace before lookup, so
  corrupted identifiers like ``"Windo ws_to_refactor"`` still resolve.
- Empty / comment-only own_conditions are treated as no conditions.
- A missing BB reference emits a MissingBuildingBlock warning, NOT an error.
- A circular dependency raises ResolutionError with the cycle path.
- Regex syntax is NOT validated (deferred to M4).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.schemas.resolved_detection import (
    ResolvedDetection,
    ResolutionError,
    ResolutionWarning,
)
from app.schemas.rules import BuildingBlock, Rule, RulesFile
from app.services.constants import strip_yaml_values

logger = logging.getLogger(__name__)

# Pattern to detect comment-only lines (# ...) or pure whitespace
_COMMENT_ONLY_RE = re.compile(r"^\s*(#.*)?$")


def _normalize_bb_id(bb_id: str) -> str:
    """Normalize a BB ID by removing ALL internal whitespace.

    This handles corrupted identifiers in shared_bbs.yaml such as
    ``"Windo ws_to_refactor"`` → ``"Windows_to_refactor"``.
    """
    return "".join(bb_id.split())


def _is_empty_conditions(text: str) -> bool:
    """Return True if own_conditions is empty, whitespace-only, or only comments."""
    if not text or not text.strip():
        return True
    # Check if every line is empty or a comment
    return all(_COMMENT_ONLY_RE.match(line) for line in text.splitlines())


def load_shared_bbs(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load shared building blocks from YAML and return a normalized lookup.

    Returns a dict keyed by normalized bb_id (whitespace-stripped).
    Each value is the raw dict from the YAML with string values stripped.
    """
    path = Path(path)
    if not path.exists():
        logger.warning("Shared BBs file not found: %s", path)
        return {}

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}

    cleaned = strip_yaml_values(raw)
    entries = cleaned.get("shared_building_blocks", [])
    if not isinstance(entries, list):
        return {}

    lookup: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        bb_id = entry.get("bb_id", "")
        if not bb_id:
            continue
        norm_id = _normalize_bb_id(bb_id)
        lookup[norm_id] = entry

    return lookup


def _build_combined_lookup(
    rule: Rule,
    shared_bbs: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[ResolutionWarning]]:
    """Build a combined BB lookup: inline BBs overlaid on shared BBs.

    Inline BBs from the rule take priority over shared BBs.
    Returns (lookup, warnings_for_corrupted_normalizations).
    """
    warnings: list[ResolutionWarning] = []
    # Start with shared
    lookup: dict[str, dict[str, Any]] = dict(shared_bbs)

    # Overlay inline BBs (they win over shared when they carry conditions).
    # CSV rows only have BB names — empty inline must not wipe shared own_conditions,
    # and an unknown empty pointer must stay out of the lookup so walk reports missing.
    for bb in rule.building_blocks:
        bb_dict = bb.model_dump()
        norm_id = _normalize_bb_id(bb.bb_id)

        # Track if normalization changed the ID
        if norm_id != bb.bb_id:
            warnings.append(ResolutionWarning(
                warning_type="corrupted_id_normalized",
                bb_id=bb.bb_id,
                rule_id=rule.rule_id,
                message="Inline BB ID normalized: '%s' → '%s'" % (bb.bb_id, norm_id),
            ))

        empty = _is_empty_conditions(bb_dict.get("own_conditions", "") or "")
        deps = list(bb_dict.get("depends_on_bb") or [])
        if empty and norm_id in lookup:
            shared = lookup[norm_id]
            merged_deps = list(shared.get("depends_on_bb") or [])
            for dep in deps:
                if dep not in merged_deps:
                    merged_deps.append(dep)
            merged = dict(shared)
            merged["depends_on_bb"] = merged_deps
            lookup[norm_id] = merged
            continue
        if empty and not deps and norm_id not in lookup:
            # CSV name-only pointer: leave it out so walk reports missing BB.
            continue
        lookup[norm_id] = bb_dict

    return lookup, warnings


def resolve_rule(
    rule: Rule,
    shared_bbs: dict[str, dict[str, Any]],
) -> ResolvedDetection:
    """Resolve a single rule's BB chain into merged conditions.

    Parameters
    ----------
    rule:
        A parsed Rule from M2.
    shared_bbs:
        The shared BB lookup from ``load_shared_bbs()``.

    Returns
    -------
    ResolvedDetection
        The resolved detection with merged conditions, log source,
        and any warnings about missing or corrupted BBs.

    Raises
    ------
    ResolutionError
        If a circular dependency is detected in depends_on_bb.
    """
    lookup, warnings = _build_combined_lookup(rule, shared_bbs)

    all_conditions: list[str] = []
    visited_chain: list[str] = []
    has_real_conditions = False

    # Walk each top-level BB in the rule
    for bb in rule.building_blocks:
        if bb.level != 1:
            continue  # Only start from level-1 (rule-level) BBs
        norm_id = _normalize_bb_id(bb.bb_id)
        _walk_bb(
            norm_id,
            lookup,
            rule.rule_id,
            all_conditions,
            visited_chain,
            warnings,
            visiting=set(),
        )
        if all_conditions:
            has_real_conditions = True

    # If no level-1 BBs found, walk ALL inline BBs
    if not has_real_conditions and rule.building_blocks:
        all_conditions.clear()
        visited_chain.clear()
        for bb in rule.building_blocks:
            norm_id = _normalize_bb_id(bb.bb_id)
            if norm_id in [_normalize_bb_id(v) for v in visited_chain]:
                continue
            _walk_bb(
                norm_id,
                lookup,
                rule.rule_id,
                all_conditions,
                visited_chain,
                warnings,
                visiting=set(),
            )
        if all_conditions:
            has_real_conditions = True

    # Determine logic source
    if has_real_conditions:
        logic_source = "bb_chain"
    else:
        logic_source = "effective_fallback"
        edl = rule.effective_detection_logic.strip()
        if edl:
            all_conditions = [edl]

    # Extract referenced field names from conditions
    referenced_fields = _extract_field_names(all_conditions)

    return ResolvedDetection(
        rule_id=rule.rule_id,
        rule_name=rule.rule_name,
        merged_conditions=all_conditions,
        logic_source=logic_source,
        log_source=rule.log_source,
        referenced_fields=referenced_fields,
        bb_chain=visited_chain,
        warnings=warnings,
    )


def _walk_bb(
    bb_id: str,
    lookup: dict[str, dict[str, Any]],
    rule_id: str,
    conditions: list[str],
    chain: list[str],
    warnings: list[ResolutionWarning],
    visiting: set[str],
) -> None:
    """Recursively walk a BB and its dependencies, collecting own_conditions."""
    norm_id = _normalize_bb_id(bb_id)

    # Circular dependency check
    if norm_id in visiting:
        cycle_path = list(chain) + [norm_id]
        raise ResolutionError(
            "Circular dependency detected: %s" % " → ".join(cycle_path),
            cycle_path=cycle_path,
        )

    # Missing BB check
    if norm_id not in lookup:
        warnings.append(ResolutionWarning(
            warning_type="missing_building_block",
            bb_id=bb_id,
            rule_id=rule_id,
            message="BB '%s' (normalized: '%s') not found in inline or shared BBs" % (bb_id, norm_id),
        ))
        return

    bb_data = lookup[norm_id]
    chain.append(norm_id)
    visiting.add(norm_id)

    # Track corrupted ID normalization for shared BBs
    raw_id = bb_data.get("bb_id", "")
    if raw_id and _normalize_bb_id(raw_id) != raw_id:
        # Only add if not already warned
        already_warned = any(
            w.bb_id == raw_id and w.warning_type == "corrupted_id_normalized"
            for w in warnings
        )
        if not already_warned:
            warnings.append(ResolutionWarning(
                warning_type="corrupted_id_normalized",
                bb_id=raw_id,
                rule_id=rule_id,
                message="Shared BB ID normalized: '%s' → '%s'" % (raw_id, _normalize_bb_id(raw_id)),
            ))

    # Recurse into dependencies FIRST (depth-first, leaf conditions come first)
    depends = bb_data.get("depends_on_bb", [])
    if isinstance(depends, list):
        for dep_id in depends:
            dep_norm = _normalize_bb_id(dep_id)
            _walk_bb(dep_norm, lookup, rule_id, conditions, chain, warnings, visiting)

    # Collect own_conditions (skip empty/comment-only)
    own_conds = bb_data.get("own_conditions", "")
    if isinstance(own_conds, str) and not _is_empty_conditions(own_conds):
        conditions.append(own_conds.strip())

    visiting.discard(norm_id)


def _extract_field_names(conditions: list[str]) -> list[str]:
    """Extract unique field names from condition text fragments.

    Looks for identifiers before comparison operators like IMATCHES, =, IS.
    """
    fields: set[str] = set()
    # Pattern: word_chars before IMATCHES, =, IS NOT NULL, etc.
    field_re = re.compile(r"\b([a-z_][a-z0-9_]*)\s+(?:IMATCHES|=|IS\b|IN\b|LIKE\b)", re.IGNORECASE)
    for cond in conditions:
        for match in field_re.finditer(cond):
            name = match.group(1).lower()
            # Skip SQL keywords that look like field names
            if name not in ("and", "or", "not", "when", "event", "apply", "log"):
                fields.add(name)
    return sorted(fields)


def resolve_all_rules(
    rules_file: RulesFile,
    shared_bbs: dict[str, dict[str, Any]],
) -> list[ResolvedDetection]:
    """Resolve all rules in a RulesFile, never raising on individual failures."""
    results: list[ResolvedDetection] = []
    for rule in rules_file.rules:
        try:
            rd = resolve_rule(rule, shared_bbs)
            results.append(rd)
        except ResolutionError as e:
            logger.error("Resolution error for %s: %s", rule.rule_id, e)
            results.append(ResolvedDetection(
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                logic_source="error",
                log_source=rule.log_source,
                warnings=[ResolutionWarning(
                    warning_type="resolution_error",
                    bb_id="",
                    rule_id=rule.rule_id,
                    message=str(e),
                )],
            ))
    return results


@dataclass(frozen=True)
class ResolutionSummary:
    """Counted BB-resolution outcomes — missing BB is never a silent skip."""

    total_rules: int
    bb_chain: int
    effective_fallback: int
    errors: int
    rules_with_missing_bb: int
    missing_bb_count: int
    missing_bb_ids: tuple[str, ...]
    corrupted_ids_normalized: int


def summarize_resolution(results: list[ResolvedDetection]) -> ResolutionSummary:
    """Count bb_chain / effective_fallback / missing BB across resolved rules."""
    dangling: list[str] = []
    seen: set[str] = set()
    for result in results:
        for warning in result.warnings:
            if warning.warning_type != "missing_building_block":
                continue
            if warning.bb_id in seen:
                continue
            seen.add(warning.bb_id)
            dangling.append(warning.bb_id)
    return ResolutionSummary(
        total_rules=len(results),
        bb_chain=sum(1 for r in results if r.logic_source == "bb_chain"),
        effective_fallback=sum(1 for r in results if r.logic_source == "effective_fallback"),
        errors=sum(1 for r in results if r.logic_source == "error"),
        rules_with_missing_bb=sum(
            1 for r in results
            if any(w.warning_type == "missing_building_block" for w in r.warnings)
        ),
        missing_bb_count=len(dangling),
        missing_bb_ids=tuple(sorted(dangling)),
        corrupted_ids_normalized=sum(
            sum(1 for w in r.warnings if w.warning_type == "corrupted_id_normalized")
            for r in results
        ),
    )


def print_resolution_report(results: list[ResolvedDetection]) -> None:
    """Print a human-readable report of BB resolution results."""
    summary = summarize_resolution(results)
    total = summary.total_rules
    fully_resolved = summary.bb_chain
    fallback = summary.effective_fallback
    errors = summary.errors
    rules_with_missing = summary.rules_with_missing_bb
    corrupted_normalized = summary.corrupted_ids_normalized
    dangling_ids = set(summary.missing_bb_ids)

    print("=== BB Resolution Report ===")
    print("  Total rules              : %d" % total)
    print("  Fully resolved (bb_chain): %d" % fully_resolved)
    print("  Effective fallback       : %d" % fallback)
    print("  Errors                   : %d" % errors)
    print("  Rules with missing BBs   : %d" % rules_with_missing)
    print("  Corrupted IDs normalized : %d" % corrupted_normalized)
    if dangling_ids:
        print("  Dangling BB IDs          : %s" % sorted(dangling_ids))
    else:
        print("  Dangling BB IDs          : (none)")
    print()

    for r in results:
        cond_count = len(r.merged_conditions)
        warn_count = len(r.warnings)
        field_count = len(r.referenced_fields)
        chain_len = len(r.bb_chain)
        status = "OK" if r.logic_source == "bb_chain" else r.logic_source.upper()
        print("  %-15s  [%s]  conditions=%d  fields=%d  chain=%d  warnings=%d" % (
            r.rule_id, status, cond_count, field_count, chain_len, warn_count))
        if r.warnings:
            for w in r.warnings:
                print("    ⚠ %s: %s" % (w.warning_type, w.message))

    print("=" * 40)
