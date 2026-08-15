"""Shared constants and helpers for the QRadar rules pipeline.

M2 — constants.py
"""

from __future__ import annotations

from typing import Any

# QRadar system-indexed fields — verified against AQL docs.
# These are the fast-path columns in every event; filters on these
# are pushed down to the index and should come first in generated AQL.
INDEXED_FIELDS: frozenset[str] = frozenset({
    "qid",
    "logsourceid",
    "devicetype",
    "domainid",
})

# eventid is a high-cardinality semantic filter (not a system index column)
# but is treated specially by the AQL emitter because it appears in almost
# every rule condition.
SEMANTIC_FILTER_FIELDS: frozenset[str] = frozenset({
    "eventid",
    "event_id",
})

# LAST window is the mandatory perf anchor — emit blocks if missing.
# Indexed-first ordering is a warning, not a block.
MANDATORY_PERF_ANCHOR = "LAST"

# Canonical log source map — maps QRadar log source display names to the
# canonical keys used in tenant drl_matrix (same keys the M1 tests seed:
# windows_event_log, proxy_log, email_gateway, sysmon).
# Unknown log sources map to themselves lowercased (see canonical_log_source).
CANONICAL_LOG_SOURCES: dict[str, str] = {
    "microsoft windows security event log": "windows_event_log",
    "sysmon": "sysmon",
}


def canonical_log_source(raw: str) -> str:
    """Normalize a log source display name to its canonical drl_matrix key.

    Known display names (e.g. "Microsoft Windows Security Event Log") map to
    canonical keys; unknown sources map to themselves lowercased/stripped.
    """
    normalized = raw.strip().lower()
    return CANONICAL_LOG_SOURCES.get(normalized, normalized)


def strip_yaml_values(obj: Any) -> Any:
    """Recursively strip leading/trailing whitespace from all string values.

    Works on dicts, lists, and scalars. Non-string leaves are returned as-is.
    Designed to be called once on the raw YAML output before schema validation,
    so that dirty fixtures with trailing spaces (e.g. ``"INC_0001000 "``) are
    cleaned uniformly.
    """
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        return {
            (k.strip() if isinstance(k, str) else k): strip_yaml_values(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [strip_yaml_values(item) for item in obj]
    # int, float, bool, None — pass through
    return obj
