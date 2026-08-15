#!/usr/bin/env python
"""M6.2 — live coverage smoke: real Threadlinqs feed → M6.1 coverage analysis.

Closes the loop: fetch a live threat bundle via the M1 MCP client, normalize it,
then run the M6.1 coverage analyzer for the three seeded tenants. No LLM, no router.

Usage (from backend/ with the venv interpreter):
    .venv\\Scripts\\python.exe scripts/coverage_live_smoke.py TL-2026-1693

If THREADLINQS_API_KEY / settings.threadlinqs_api_key is empty, prints a skip
message and exits 0. The API key is never printed or logged.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import yaml

# Ensure the backend package (and the tests namespace) is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.constants import strip_yaml_values  # noqa: E402
from app.services.coverage.analyzer import (  # noqa: E402
    COVERAGE_GAP,
    COVERED,
    DRL_BLIND,
    FIELD_PARTIAL,
    SYSMON_BLIND,
    analyze_coverage,
)

DEFAULT_ID = "TL-2026-1693"
_FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "full_rules85.yaml")

# Inline seeded tenants — the exact M1 smoke profiles. None has a sysmon key,
# so every sysmon_required rule is SYSMON_BLIND for all three.
TENANTS = [
    {
        "id": 1, "name": "finance", "sector": "finance", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 3, "proxy_log": 2, "email_gateway": 1},
    },
    {
        "id": 2, "name": "energy", "sector": "energy", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 4, "proxy_log": 3, "email_gateway": 3},
    },
    {
        "id": 3, "name": "critical_infrastructure", "sector": "critical_infrastructure", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 1, "proxy_log": 0, "email_gateway": 0},
    },
]


def _get_api_key() -> str:
    """Read the key from pydantic settings (canonical, reads backend/.env),
    falling back to the THREADLINQS_API_KEY env var. Never printed anywhere."""
    try:
        from app.core.config import settings
        if settings.threadlinqs_api_key:
            return settings.threadlinqs_api_key
    except Exception:
        pass
    return os.environ.get("THREADLINQS_API_KEY", "")


def _parse_mcp_result(result: object) -> object:
    """Parse MCP call_tool result into a Python object.

    Identical copy of scripts/smoke_threadlinqs.py::_parse_mcp_result.
    """
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


def _flatten_bundle(bundle: dict) -> dict:
    """Merge the real API envelope {threat, iocs, mitre_technique_ids, ...} into
    a flat dict the normalizer understands. Same shaping as smoke_threadlinqs.py."""
    if "threat" in bundle and isinstance(bundle["threat"], dict):
        flat = dict(bundle["threat"])
    else:
        flat = dict(bundle)
    if "iocs" in bundle and "iocs" not in flat:
        flat["iocs"] = bundle["iocs"]
    technique_ids = set()
    for tid in (bundle.get("mitre_technique_ids") or []):
        technique_ids.add(tid)
    if isinstance(flat.get("mitre_attack"), dict):
        for tid in (flat["mitre_attack"].get("technique_ids", []) or []):
            technique_ids.add(tid)
    if technique_ids:
        flat.setdefault("techniques", [])
        for tid in technique_ids:
            flat["techniques"].append({"id": tid, "name": tid})
    return flat


def _build_tactic_map(raw_bundle: dict, ttps: list[str]) -> dict[str, str]:
    """technique_id → tactic name. Prefer per-technique tactic info carried in
    the bundle; fall back to the shared table in app.services.mitre_meta."""
    from app.services.mitre_meta import TTP_TACTICS as fallback

    tactic_map: dict[str, str] = {}
    # Bundle-provided per-technique tactic, if present (techniques/mitre_attack).
    section = raw_bundle.get("techniques")
    if isinstance(raw_bundle.get("mitre_attack"), dict):
        section = section or raw_bundle["mitre_attack"].get("techniques")
    if isinstance(section, list):
        for item in section:
            if not isinstance(item, dict):
                continue
            tid = str(item.get("id") or item.get("technique_id") or "").upper().strip()
            tactic = item.get("tactic") or item.get("tactic_name") or item.get("tactic_id")
            if tid and tactic:
                tactic_map[tid] = str(tactic).strip()

    for tid in ttps:
        tid_norm = str(tid).upper().strip()
        tactic_map.setdefault(tid_norm, fallback.get(tid_norm, "unknown"))
    return tactic_map


def _print_report(tenant_name: str, threat, report) -> None:
    counts = report.summary.status_counts
    total = len(threat.iocs)
    network = sum(1 for i in threat.iocs if i.source == "network")
    file_c = sum(1 for i in threat.iocs if i.source == "file")

    print("=" * 64)
    print("=== tenant: %s ===" % tenant_name)
    print("title     : %s" % threat.title)
    print("actor     : %s (confidence: %s)" % (threat.actor or "(none)", threat.actor_confidence or "-"))
    print("IOCs      : %d  (network=%d, file=%d)" % (total, network, file_c))
    print("total TTPs: %d  covered: %d" % (len(report.techniques), counts[COVERED]))
    print("FIELD_PARTIAL: %d  DRL_BLIND: %d  SYSMON_BLIND: %d  COVERAGE_GAP: %d" % (
        counts[FIELD_PARTIAL], counts[DRL_BLIND], counts[SYSMON_BLIND], counts[COVERAGE_GAP]))
    print("top 5 blind spots by priority:")
    for rec in report.summary.blind_spots[:5]:
        reason = ", ".join(rec.covering_rule_ids) if rec.covering_rule_ids else "no enabled rule covers"
        print("  %-10s %-13s prio=%-7s %s" % (rec.technique_id, rec.primary_status, rec.priority, reason))
    print("per-tactic coverage ratio:")
    for tactic, ratio in report.summary.tactic_coverage.items():
        print("  %s: %s" % (tactic, ratio))
    print()


async def main() -> None:
    api_key = _get_api_key()
    if not api_key:
        print("SKIP: threadlinqs_api_key/THREADLINQS_API_KEY is empty. "
              "Set it in backend/.env or the environment to run this live smoke.")
        sys.exit(0)

    target_id = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ID
    print("API key loaded from settings/env (value redacted).")
    print("Target threat id: %s" % target_id)
    print()

    from app.services.threadlinqs_client import ThreadlinqsClient
    from app.services.threadlinqs_normalizer import normalize_bundle

    # Load the 14-rule fixture extract as the rulebook.
    with open(_FIXTURE, "r", encoding="utf-8") as fh:
        rules_doc = strip_yaml_values(yaml.safe_load(fh))
    rulebook = rules_doc["rules"]

    client = ThreadlinqsClient(api_key=api_key)
    try:
        print("=== Connecting to Threadlinqs MCP server ===")
        await client.connect()

        print("=== Fetching bundle: %s ===" % target_id)
        result = await client.call_tool("get_threat_bundle", {"threat_id": target_id})
        bundle = _parse_mcp_result(result)
        if not isinstance(bundle, dict):
            print("ERROR: unexpected bundle type %s: %s" % (type(bundle), str(bundle)[:300]))
            sys.exit(1)

        flat = _flatten_bundle(bundle)
        threat = normalize_bundle(flat)
        threat_dict = {
            "ttps": threat.ttps,
            "sectors": threat.sectors,
            "regions": threat.regions,
        }
        tactic_map = _build_tactic_map(threat.raw_bundle, threat.ttps)

        print()
        print("NOTE: rulebook is the 14-rule fixture extract (backend/fixtures/full_rules85.yaml), "
              "NOT the full client rulebook — output is a coverage sample, not full coverage.")
        print()

        for tenant in TENANTS:
            report = analyze_coverage(threat_dict, tenant, rulebook, tactic_map=tactic_map)
            _print_report(tenant["name"], threat, report)

    finally:
        await client.disconnect()
        print("=== Disconnected ===")


if __name__ == "__main__":
    asyncio.run(main())
