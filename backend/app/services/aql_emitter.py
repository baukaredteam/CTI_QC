"""Mini M4 AQL emitter — M6.3, ticket 02. Deterministic, no I/O.

Scoped into the management slice per ADR-0001: ``from_resolved_detection ->
emit`` only. The ``sigma-ast`` adapter and ``fp_injector`` are explicitly OUT
for this slice.

Emission rules (CHANGE_PLAN M4 / constants.py):
- The ``LAST`` window anchor is mandatory — it is always emitted. The emitter
  itself emits it, so a caller cannot forget it (block-if-missing is satisfied
  by construction).
- An explicit log source filter is always emitted first, expressed through
  ``devicetype`` — a member of ``INDEXED_FIELDS`` — so the indexed predicate
  is the first WHERE predicate.
- Conditions from the resolved detection are appended as predicates, in order.
- Sufficiency is computed ONLY from the rule's own ``custom_fields``
  availability (per lock: no fields.yaml join). A referenced field that is
  missing from ``custom_fields`` is a blind field; ``partial`` availability
  is a partial field.
- ``regex_guard`` scans all conditions; a degraded IMATCHES pattern makes the
  rule not copy-ready and attaches a ``REGEX_DEGRADED`` warning.
- ``copy_ready`` is True only when every referenced field is fully available
  AND no degraded regex was found.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from app.schemas.aql import AQLRule, EmitterWarning, SufficiencyResult
from app.schemas.resolved_detection import ResolvedDetection
from app.services.constants import INDEXED_FIELDS, SEMANTIC_FILTER_FIELDS
from app.services.regex_guard import guard_conditions

# Mandatory perf anchor value emitted into every AQL string.
DEFAULT_LAST_WINDOW = "LAST 5 MINUTES"

_LOG_SOURCE_FILTER = "LOGSOURCETYPENAME(devicetype) = '{source}'"


def _referenced_fields(detection: ResolvedDetection) -> list[str]:
    """Field names the resolved detection actually references (normalized)."""
    return [str(f).strip() for f in (detection.referenced_fields or []) if str(f).strip()]


def _availability_lookup(custom_fields: Sequence) -> dict[str, str]:
    """Map lowercased field name → availability, from the rule's own fields.

    Accepts both plain dicts and pydantic ``CustomField`` models.
    """
    lookup: dict[str, str] = {}

    def _get(item, key: str) -> str:
        if isinstance(item, Mapping):
            return str(item.get(key) or "")
        return str(getattr(item, key, "") or "")

    for cf in custom_fields or []:
        name = _get(cf, "name").strip().lower()
        if name:
            lookup[name] = _get(cf, "availability").strip().lower()
    return lookup


def _build_aql(detection: ResolvedDetection) -> str:
    """Assemble the AQL string: log filter first, then conditions, then LAST."""
    log_filter = _LOG_SOURCE_FILTER.format(source=detection.log_source.strip())
    conditions = [c for c in (detection.merged_conditions or []) if c and c.strip()]
    predicates = [log_filter] + ["(" + c.strip() + ")" for c in conditions]
    return (
        "SELECT * FROM events WHERE "
        + " AND ".join(predicates)
        + " "
        + DEFAULT_LAST_WINDOW
    )


def _compute_sufficiency(
    referenced: list[str],
    availability: dict[str, str],
) -> SufficiencyResult:
    """Sufficiency from the rule's own custom_fields availability.

    full → checked; partial → partial; missing/unknown → blind.
    """
    checked: list[str] = []
    partial: list[str] = []
    blind: list[str] = []
    for field in referenced:
        key = field.lower()
        if key in SEMANTIC_FILTER_FIELDS or key in INDEXED_FIELDS:
            # Built-in index/semantic columns are always present on every
            # event; they count as checked by construction (constants.py).
            checked.append(field)
            continue
        avail = availability.get(key, "")
        if avail == "full":
            checked.append(field)
        elif avail == "partial":
            partial.append(field)
        else:
            blind.append(field)

    total = len(referenced) or 1
    pct = round((len(checked) / total) * 100, 1)
    return SufficiencyResult(
        sufficiency_pct=pct,
        fields_checked=checked,
        partial_fields=partial,
        blind_fields=blind,
    )


def emit(
    detection: ResolvedDetection,
    custom_fields: Sequence[Mapping],
) -> AQLRule:
    """Emit a copy-ready AQL bundle for a resolved detection.

    Args:
        detection: The M3 ``ResolvedDetection`` (BB-chain-resolved conditions,
            log source, referenced fields).
        custom_fields: The rule's own ``custom_fields`` (name + availability).
            Sufficiency is computed from this list ONLY.

    Returns:
        AQLRule with aql, copy_ready, warnings, and sufficiency.
    """
    guard_warnings = guard_conditions(detection.merged_conditions or [])

    referenced = _referenced_fields(detection)
    availability = _availability_lookup(custom_fields)
    sufficiency = _compute_sufficiency(referenced, availability)

    warnings: list[EmitterWarning] = list(guard_warnings)

    if sufficiency.partial_fields or sufficiency.blind_fields:
        warnings.append(EmitterWarning(
            code="PARTIAL_FIELD_AVAILABILITY",
            severity="warning",
            message=(
                "Rule references fields that are not fully available: "
                f"partial={sufficiency.partial_fields or 'none'}, "
                f"blind={sufficiency.blind_fields or 'none'}"
            ),
        ))

    has_degraded_regex = any(
        w.code == "REGEX_DEGRADED" for w in guard_warnings
    )
    copy_ready = (
        not has_degraded_regex
        and not sufficiency.partial_fields
        and not sufficiency.blind_fields
    )

    return AQLRule(
        rule_id=detection.rule_id,
        log_source=detection.log_source,
        aql=_build_aql(detection),
        copy_ready=copy_ready,
        warnings=warnings,
        sufficiency=sufficiency,
    )


def from_resolved_detection(
    detection: ResolvedDetection,
    custom_fields: Sequence[Mapping],
) -> AQLRule:
    """Adapter entry point — delegates to ``emit`` (ADR-0001 shape)."""
    return emit(detection, custom_fields)
