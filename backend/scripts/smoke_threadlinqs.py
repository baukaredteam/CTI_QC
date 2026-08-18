#!/usr/bin/env python
"""Manual smoke test for Threadlinqs MCP integration.

NOT for CI — run manually when THREADLINQS_API_KEY is set.

Usage (from backend/ with venv active):
    python scripts/smoke_threadlinqs.py                           # defaults
    python scripts/smoke_threadlinqs.py TL-2026-1693 TL-2026-1707

If THREADLINQS_API_KEY is absent, prints a skip message and exits 0.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ensure the backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DEFAULT_IDS = ["TL-2026-1693", "TL-2026-1707"]

# Ticket 11: representative techniques of the canonical TL-2026-1693 campaign
# (KEGOC finance/energy/critical-infra demo) probed by the live
# predict_mitre_transitions smoke — deterministic, quota-bounded (3 ids).
_SMOKE_TECHNIQUE_IDS = ["T1027", "T1078", "T1003.002"]

# --- Inline test tenants (same as M1 unit tests) ---

TENANTS = [
    {
        "id": 1, "name": "KEGOC Finance", "sector": "finance", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 3, "proxy_log": 2, "email_gateway": 1},
    },
    {
        "id": 2, "name": "KEGOC Energy", "sector": "energy", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 4, "proxy_log": 3, "email_gateway": 3},
    },
    {
        "id": 3, "name": "KEGOC Critical Infra", "sector": "critical_infrastructure", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 1, "proxy_log": 0, "email_gateway": 0},
    },
]

RULEBOOK = [
    {"id": "R1", "enabled": True, "technique_ids": ["T1059.001"], "required_log_source": "windows_event_log"},
    {"id": "R2", "enabled": True, "technique_ids": ["T1071.001"], "required_log_source": "proxy_log"},
    {"id": "R3", "enabled": True, "technique_ids": ["T1566.001"], "required_log_source": "email_gateway"},
]


def _get_api_key() -> str | None:
    """Get the API key from env or pydantic settings."""
    key = os.environ.get("THREADLINQS_API_KEY", "")
    if key:
        return key
    try:
        from app.core.config import settings
        if settings.threadlinqs_api_key:
            return settings.threadlinqs_api_key
    except Exception:
        pass
    return None


class SmokeStatus:
    """Ticket 11 statuses for the per-tool live smoke checks."""

    PASS = "PASS"
    EMPTY_FALLBACK = "EMPTY_FALLBACK"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass(frozen=True)
class SmokeResult:
    """Shape-only summary of one live MCP tool check (never raw data)."""

    tool: str
    status: str
    summary: str = ""

    def __str__(self) -> str:
        return "[%s] %s %s" % (self.status, self.tool, self.summary)


def _shape_counts(payload: dict) -> str:
    """Top-level key → element count summary for a tool envelope (keys only)."""
    counts = []
    for key, value in payload.items():
        if isinstance(value, list):
            counts.append("%s=%d" % (key, len(value)))
        elif isinstance(value, dict):
            counts.append("%s={%s}" % (key, ",".join(value.keys())[:80]))
    return "; ".join(counts) or "no list/dict values"


async def smoke_get_threat_hunting_bundle(client, threat_id: str) -> SmokeResult:
    """get_threat_hunting_bundle shape check (verified schema {threat_id})."""
    try:
        raw = await client.call_tool("get_threat_hunting_bundle", {"threat_id": threat_id})
    except Exception as exc:
        return SmokeResult("get_threat_hunting_bundle", SmokeStatus.ERROR, "raised %s" % type(exc).__name__)
    payload = _parse_mcp_result(raw)
    if not isinstance(payload, dict) or not payload:
        return SmokeResult("get_threat_hunting_bundle", SmokeStatus.EMPTY_FALLBACK, "empty/non-dict envelope")
    return SmokeResult(
        "get_threat_hunting_bundle",
        SmokeStatus.PASS,
        "keys=%s counts[%s]" % (sorted(payload.keys()), _shape_counts(payload)),
    )


async def smoke_predict_mitre_transitions(client, technique_ids) -> SmokeResult:
    """predict_mitre_transitions shape check (verified schema, forward/5/any)."""
    ids = [str(tid) for tid in (technique_ids or [])][:3]
    if not ids:
        return SmokeResult("predict_mitre_transitions", SmokeStatus.SKIP, "no technique ids supplied")
    errored = 0
    empties = 0
    next_counts = []
    for tid in ids:
        try:
            raw = await client.call_tool(
                "predict_mitre_transitions",
                {"technique_id": tid, "direction": "forward", "top_n": 5, "basis": "any"},
            )
        except Exception as exc:
            errored += 1
            continue
        payload = _parse_mcp_result(raw)
        if not isinstance(payload, dict) or not payload:
            empties += 1
            continue
        nxt = payload.get("predicted_next_techniques")
        next_counts.append(len(nxt) if isinstance(nxt, list) else 0)
    if errored == len(ids):
        return SmokeResult("predict_mitre_transitions", SmokeStatus.ERROR, "all %d ids raised" % errored)
    if errored or empties == len(ids) or all(c == 0 for c in next_counts):
        return SmokeResult(
            "predict_mitre_transitions",
            SmokeStatus.EMPTY_FALLBACK,
            "errored=%d empty=%d next_counts=%s" % (errored, empties, next_counts),
        )
    return SmokeResult(
        "predict_mitre_transitions",
        SmokeStatus.PASS,
        "probed=%d next_counts=%s" % (len(next_counts), next_counts),
    )


async def smoke_get_attack_flow(client, threat_id: str) -> SmokeResult:
    """get_attack_flow shape check (verified schema {threat_id})."""
    try:
        raw = await client.call_tool("get_attack_flow", {"threat_id": threat_id})
    except Exception as exc:
        return SmokeResult("get_attack_flow", SmokeStatus.ERROR, "raised %s" % type(exc).__name__)
    payload = _parse_mcp_result(raw)
    if not isinstance(payload, dict) or not payload:
        return SmokeResult("get_attack_flow", SmokeStatus.EMPTY_FALLBACK, "empty/non-dict envelope")
    return SmokeResult(
        "get_attack_flow",
        SmokeStatus.PASS,
        "keys=%s counts[%s]" % (sorted(payload.keys()), _shape_counts(payload)),
    )


async def smoke_export_stix(client, threat_id: str) -> SmokeResult:
    """export_stix check — NOT_AVAILABLE unless the live v7.1.0 registry
    advertises it; never faked (issue 06B needs owner decision/schema)."""
    try:
        tools = await client.list_tools()
        registered = {t.name for t in tools}
    except Exception:
        registered = set()
    if "export_stix" not in registered:
        return SmokeResult(
            "export_stix",
            SmokeStatus.NOT_AVAILABLE,
            "absent from v7.1.0 registry; no contract invented — offline STIX fixture (ticket 01) is the documented fallback",
        )
    try:
        raw = await client.call_tool("export_stix", {"threat_id": threat_id})
    except Exception as exc:
        return SmokeResult("export_stix", SmokeStatus.ERROR, "raised %s" % type(exc).__name__)
    payload = _parse_mcp_result(raw)
    if not isinstance(payload, dict) or not payload:
        return SmokeResult("export_stix", SmokeStatus.EMPTY_FALLBACK, "empty/non-dict envelope")
    return SmokeResult(
        "export_stix",
        SmokeStatus.PASS,
        "keys=%s counts[%s]" % (sorted(payload.keys()), _shape_counts(payload)),
    )


def _print_ioc_summary(threat) -> None:
    """Print IOC count with network/file split and verdict counter."""
    total = len(threat.iocs)
    network_count = sum(1 for ioc in threat.iocs if ioc.source == "network")
    file_count = sum(1 for ioc in threat.iocs if ioc.source == "file")
    other_count = total - network_count - file_count

    parts = ["network=%d" % network_count, "file=%d" % file_count]
    if other_count:
        parts.append("other=%d" % other_count)
    split_str = ", ".join(parts)
    print("  IOCs      : %d  (%s)" % (total, split_str))

    if threat.iocs:
        verdicts = Counter()
        for ioc in threat.iocs:
            if ioc.classification:
                verdicts[ioc.classification.verdict.value] += 1
            else:
                verdicts["unknown"] += 1
        print("  verdicts  : %s" % dict(verdicts))


async def _process_bundle(client, target_id: str, normalizer, scorer) -> None:
    """Fetch, normalize, and score a single threat bundle."""
    print("=" * 60)
    print("=== Fetching bundle: %s ===" % target_id)
    try:
        bundle_result = await client.call_tool("get_threat_hunting_bundle", {"threat_id": target_id})
        bundle = _parse_mcp_result(bundle_result)
    except Exception as e:
        print("Failed with get_threat_hunting_bundle: %s" % e)
        return

    if not isinstance(bundle, dict):
        print("Unexpected bundle type: %s" % type(bundle))
        raw_preview = str(bundle)[:500]
        print("Raw: %s" % raw_preview)
        return

    print("Bundle keys: %s" % list(bundle.keys()))

    # The real API returns {threat, iocs, simulations, transcripts, mitre_technique_ids, ...}
    # Merge into a flat structure the normalizer understands
    flat_bundle = {}
    if "threat" in bundle and isinstance(bundle["threat"], dict):
        flat_bundle = dict(bundle["threat"])
    else:
        flat_bundle = dict(bundle)

    # Inject IOCs from top-level — may be a dict (category-grouped) or list
    if "iocs" in bundle and "iocs" not in flat_bundle:
        flat_bundle["iocs"] = bundle["iocs"]
    # Inject MITRE technique IDs from bundle top-level and threat.mitre_attack
    technique_ids = set()
    if "mitre_technique_ids" in bundle:
        for tid in (bundle["mitre_technique_ids"] or []):
            technique_ids.add(tid)
    if "mitre_attack" in flat_bundle and isinstance(flat_bundle["mitre_attack"], dict):
        for tid in (flat_bundle["mitre_attack"].get("technique_ids", []) or []):
            technique_ids.add(tid)
    if technique_ids:
        flat_bundle.setdefault("techniques", [])
        for tid in technique_ids:
            flat_bundle["techniques"].append({"id": tid, "name": tid})

    print("Flat bundle keys: %s" % list(flat_bundle.keys())[:15])
    print()

    # Normalize
    print("--- Normalizing ---")
    threat = normalizer(flat_bundle)
    print("  bundle_id : %s" % threat.bundle_id)
    print("  title     : %s" % threat.title)
    print("  actor     : %s (confidence: %s)" % (threat.actor, threat.actor_confidence))
    _print_ioc_summary(threat)
    print("  behavioral: %d" % len(threat.behavioral))
    print("  sectors   : %d — %s" % (len(threat.sectors), threat.sectors))
    print("  regions   : %d — %s" % (len(threat.regions), threat.regions))
    ttp_preview = threat.ttps[:10]
    print("  TTPs      : %d — %s" % (len(threat.ttps), ttp_preview))
    print()

    # Score against 3 tenants
    print("--- Per-tenant scoring ---")
    threat_dict = {
        "sectors": threat.sectors,
        "regions": threat.regions,
        "ttps": threat.ttps,
        "iocs": threat.iocs,
        "actor_confidence": threat.actor_confidence,
    }
    for tenant in TENANTS:
        result = scorer(threat_dict, tenant, RULEBOOK)
        print("  %-25s  score=%5.1f  zone=%-6s  "
              "vis_ttps=%d/%d  "
              "sectors=%s  regions=%s" % (
                  result.tenant_name, result.score, result.zone,
                  result.visible_ttp_count, result.total_ttp_count,
                  result.matching_sectors, result.matching_regions))
    print()


async def main() -> None:
    api_key = _get_api_key()
    if not api_key:
        print("SKIP: THREADLINQS_API_KEY not set. Set it in .env or environment to run this smoke test.")
        sys.exit(0)

    # configured=true only — never print the key or any prefix of it
    print("configured=true")
    print()

    # Determine target IDs: from argv or defaults
    if len(sys.argv) > 1:
        target_ids = sys.argv[1:]
    else:
        target_ids = list(DEFAULT_IDS)

    print("Target threat IDs: %s" % target_ids)
    print()

    from app.services.threadlinqs_client import ThreadlinqsClient
    from app.services.threadlinqs_normalizer import normalize_bundle
    from app.services.relevance_scorer import score_threat

    client = ThreadlinqsClient(api_key=api_key)

    try:
        # 1. Connect and list tools
        print("=== Connecting to Threadlinqs MCP server ===")
        await client.connect()
        tools = await client.list_tools()
        tool_count = len(tools)
        print("Available tools (%d):" % tool_count)
        for t in tools:
            name = t.name if hasattr(t, "name") else str(t)
            print("  - %s" % name)
        print()

        # 2. Get recent threats (informational only — does NOT change target_ids)
        print("=== Fetching recent threats (limit 3, informational) ===")
        recent_result = await client.call_tool("get_recent_threats", {"limit": 3})
        recent_data = _parse_mcp_result(recent_result)
        if isinstance(recent_data, dict):
            recent_threats = recent_data.get("items", recent_data.get("threats", recent_data.get("data", [])))
            if not isinstance(recent_threats, list):
                recent_threats = [recent_data]
        elif isinstance(recent_data, list):
            recent_threats = recent_data
        else:
            recent_threats = []

        print("Got %d recent threats" % len(recent_threats))
        if recent_threats and isinstance(recent_threats[0], dict):
            first_keys = list(recent_threats[0].keys())[:15]
            print("  First threat keys: %s" % first_keys)
        for i, t in enumerate(recent_threats[:3]):
            if isinstance(t, dict):
                tid = t.get("threat_id", t.get("id", t.get("bundle_id", "?")))
                title = t.get("title", t.get("name", "?"))
            else:
                tid = str(t)[:40]
                title = ""
            print("  [%d] %s: %s" % (i + 1, tid, title))
        print()

        # 3. Process each target bundle
        for target_id in target_ids:
            await _process_bundle(client, target_id, normalize_bundle, score_threat)

        # 4. Ticket 11: four verified MCP tool shape checks (shape summaries only)
        print("=== Ticket 11 — four verified tool shape checks ===")
        for target_id in target_ids:
            print("  %s" % await smoke_get_threat_hunting_bundle(client, target_id))
            print("  %s" % await smoke_get_attack_flow(client, target_id))
            print("  %s" % await smoke_export_stix(client, target_id))
        print("  %s" % await smoke_predict_mitre_transitions(client, _SMOKE_TECHNIQUE_IDS))
        print()

    finally:
        await client.disconnect()
        print("=== Disconnected ===")


def _parse_mcp_result(result: object) -> object:
    """Parse MCP call_tool result into a Python object."""
    # MCP results come as CallToolResult with content list
    if hasattr(result, "content"):
        contents = result.content
        if isinstance(contents, list) and len(contents) > 0:
            item = contents[0]
            if hasattr(item, "text"):
                try:
                    return json.loads(item.text)
                except (json.JSONDecodeError, TypeError):
                    return item.text
            return item
    # Fallback: try direct JSON parse
    if isinstance(result, str):
        try:
            return json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return result
    if isinstance(result, dict):
        return result
    return result


if __name__ == "__main__":
    asyncio.run(main())
