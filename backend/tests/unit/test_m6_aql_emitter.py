"""M6.3 ticket 02 — mini M4 AQL emitter.

Covers the locked CHANGE_PLAN / ADR-0001 contract for
``from_resolved_detection -> emit``:
- Output contains the mandatory ``LAST`` window anchor.
- Output contains an explicit log source filter.
- The indexed-filter predicate (``devicetype``, from ``INDEXED_FIELDS``)
  is first.
- A rule whose referenced custom fields are all fully available emits
  ``copy_ready=True``.
- A rule with a partially-available field emits ``copy_ready=False`` with a
  sufficiency warning.
- A rule with a degraded IMATCHES pattern (via ``regex_guard``) emits
  ``copy_ready=False`` with a ``REGEX_DEGRADED`` warning.

Uses the real M3 ``bb_resolver`` to obtain the ``ResolvedDetection`` from a
parsed rule (the requested reuse). Asserts external behavior only, no LLM.
"""

from __future__ import annotations

from app.schemas.rules import CustomField, Rule
from app.services.aql_emitter import (  # type: ignore[import-not-found]
    DEFAULT_LAST_WINDOW,
    emit,
    from_resolved_detection,
)
from app.services.bb_resolver import resolve_rule


def _rule(
    rule_id="R1",
    conditions=None,
    *,
    log_source="Microsoft Windows Security Event Log",
    custom_fields=None,
):
    return Rule(
        rule_id=rule_id,
        rule_name=rule_id,
        log_source=log_source,
        building_blocks=[
            {
                "bb_id": "BB_root",
                "bb_name": rule_id,
                "level": 1,
                "depends_on_bb": [],
                "own_conditions": "\n".join(conditions or ["event_id = 4767"]),
            }
        ],
        custom_fields=custom_fields or [],
    )


def _cf(name, availability="full"):
    return CustomField(name=name, availability=availability)


def _detection(rule: Rule):
    return resolve_rule(rule, shared_bbs={})


# ── Structure: LAST window, log filter, indexed-first ───────────────────────


def test_emit_contains_last_window():
    rule = _rule()
    aql = emit(_detection(rule), custom_fields=rule.custom_fields)
    assert aql.aql
    assert "LAST" in aql.aql


def test_emit_contains_log_filter():
    rule = _rule(log_source="Microsoft Windows Security Event Log")
    aql = emit(_detection(rule), custom_fields=rule.custom_fields)
    assert "Security Event Log" in aql.aql


def test_emit_indexed_filter_is_first():
    rule = _rule()
    aql = emit(_detection(rule), custom_fields=rule.custom_fields)
    indexed_pos = aql.aql.find("devicetype")
    assert indexed_pos >= 0
    event_pos = aql.aql.find("event_id")
    assert event_pos == -1 or indexed_pos < event_pos


def test_default_last_window_value_in_aql():
    assert DEFAULT_LAST_WINDOW  # sanity on the shared constant
    aql = emit(_detection(_rule()), custom_fields=[])
    assert DEFAULT_LAST_WINDOW.upper() in aql.aql.upper()


# ── copy_ready gate from availability sufficiency ────────────────────────────


def test_copy_ready_when_all_fields_full():
    rule = _rule(
        conditions=["proc_usr_name IMATCHES '.*alice.*'", "event_id = 4767"],
        custom_fields=[_cf("proc_usr_name")],
    )
    aql = emit(_detection(rule), custom_fields=rule.custom_fields)
    assert aql.copy_ready is True
    assert aql.warnings == []


def test_copy_ready_false_on_partial_field():
    rule = _rule(
        conditions=["CommandLine IS NOT NULL", "event_id = 4688"],
        custom_fields=[_cf("CommandLine", "partial")],
    )
    aql = emit(_detection(rule), custom_fields=rule.custom_fields)
    assert aql.copy_ready is False
    codes = {w.code for w in aql.warnings}
    assert "PARTIAL_FIELD_AVAILABILITY" in codes


def test_sufficiency_counts_partial_and_blind_fields():
    rule = _rule(
        conditions=[
            "CommandLine IS NOT NULL",
            "MissingField IMATCHES '.*x.*'",
            "event_id = 4688",
        ],
        custom_fields=[_cf("CommandLine", "partial")],
    )
    aql = emit(_detection(rule), custom_fields=rule.custom_fields)
    assert aql.sufficiency is not None
    partial_lower = [f.lower() for f in aql.sufficiency.partial_fields]
    blind_lower = [f.lower() for f in aql.sufficiency.blind_fields]
    assert "commandline" in partial_lower
    assert "missingfield" in blind_lower


# ── copy_ready gate via regex_guard ──────────────────────────────────────────


def test_copy_ready_false_on_degraded_regex():
    rule = _rule(
        conditions=["proc_file_path IMATCHES '.\\cmd.exe'", "event_id = 4688"],
        custom_fields=[_cf("proc_file_path")],
    )
    aql = emit(_detection(rule), custom_fields=rule.custom_fields)
    assert aql.copy_ready is False
    codes = {w.code for w in aql.warnings}
    assert "REGEX_DEGRADED" in codes


def test_copy_ready_false_keeps_aql_truthy():
    # Even a non-copy-ready rule still carries a real query string for the
    # analyst to review — the flag tells them to check it before pasting.
    rule = _rule(
        conditions=["cmdline IMATCHES '[invalid'", "event_id = 4688"],
        custom_fields=[],
    )
    aql = emit(_detection(rule), custom_fields=rule.custom_fields)
    assert aql.aql
    assert aql.copy_ready is False


# ── the from_resolved_detection adapter ──────────────────────────────────────


def test_from_resolved_detection_is_adapter_over_emit():
    rule = _rule(custom_fields=[])
    via_adapter = from_resolved_detection(_detection(rule), custom_fields=[])
    via_emit = emit(_detection(rule), custom_fields=[])
    assert via_adapter.aql == via_emit.aql
    assert via_adapter.copy_ready == via_emit.copy_ready