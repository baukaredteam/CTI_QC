#!/usr/bin/env python
"""Diagnostic: dump the raw IOC block shape from real Threadlinqs bundles."""
from __future__ import annotations
import asyncio, json, os, sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

async def main():
    key = os.environ.get("THREADLINQS_API_KEY", "")
    if not key:
        print("SKIP: no key"); return

    from app.services.threadlinqs_client import ThreadlinqsClient
    from app.services.circuit_breaker import CircuitState
    from app.services.threadlinqs_client import _rate_limiter, _breaker
    _rate_limiter._count = 0; _rate_limiter._current_day = ""
    _breaker._state = CircuitState.CLOSED; _breaker._failure_count = 0

    c = ThreadlinqsClient(api_key=key)
    await c.connect()

    # Try specific IDs known to have IOCs, then fall back to recent
    target_ids = ["TL-2026-1693", "TL-2026-1700", "TL-2026-1690"]

    # Also get recent and check which have IOCs
    res = await c.call_tool("get_recent_threats", {"limit": 10})
    data = _parse(res)
    items = data.get("items", []) if isinstance(data, dict) else []
    for item in items:
        tid = item.get("id", "")
        if tid and tid not in target_ids:
            target_ids.append(tid)

    for tid in target_ids[:6]:
        print(f"\n{'='*60}")
        print(f"Fetching bundle: {tid}")
        try:
            br = await c.call_tool("get_threat_bundle", {"threat_id": tid})
            bundle = _parse(br)
        except Exception as e:
            print(f"  FAILED: {e}"); continue

        if not isinstance(bundle, dict):
            print(f"  Not a dict: {type(bundle)}"); continue

        # Check top-level iocs
        top_iocs = bundle.get("iocs", [])
        threat_obj = bundle.get("threat", {})
        threat_iocs = threat_obj.get("iocs", []) if isinstance(threat_obj, dict) else []

        print(f"  Top-level 'iocs': type={type(top_iocs).__name__}, len={len(top_iocs) if isinstance(top_iocs, list) else 'N/A'}")
        print(f"  threat.iocs: type={type(threat_iocs).__name__}, len={len(threat_iocs) if isinstance(threat_iocs, list) else 'N/A'}")

        # Show the real structure
        ioc_block = top_iocs if top_iocs else threat_iocs
        if isinstance(ioc_block, list) and len(ioc_block) > 0:
            print(f"  IOC block is a LIST with {len(ioc_block)} items")
            # Show first 3 items
            for i, item in enumerate(ioc_block[:3]):
                print(f"    [{i}] type={type(item).__name__}")
                if isinstance(item, dict):
                    print(f"        keys={list(item.keys())}")
                    print(f"        raw={json.dumps(item, default=str)[:300]}")
                elif isinstance(item, str):
                    print(f"        value={item[:100]}")
        elif isinstance(ioc_block, dict):
            print(f"  IOC block is a DICT with keys: {list(ioc_block.keys())}")
            for k, v in ioc_block.items():
                if isinstance(v, list):
                    print(f"    '{k}': list of {len(v)} items")
                    if v:
                        print(f"      [0] type={type(v[0]).__name__}: {json.dumps(v[0], default=str)[:200]}")
                else:
                    print(f"    '{k}': {type(v).__name__} = {str(v)[:100]}")
        else:
            print(f"  IOC block empty or unexpected type")

        # Also show target_sectors and target_regions
        flat = dict(threat_obj) if isinstance(threat_obj, dict) else {}
        print(f"  target_sectors: {flat.get('target_sectors', 'MISSING')}")
        print(f"  target_regions: {flat.get('target_regions', 'MISSING')}")
        print(f"  attribution: {json.dumps(flat.get('attribution', {}), default=str)[:300]}")

        if isinstance(ioc_block, list) and len(ioc_block) > 0:
            print(f"\n  >>> FOUND IOCs! Stopping here. <<<")
            break

    await c.disconnect()

def _parse(result):
    if hasattr(result, "content"):
        contents = result.content
        if isinstance(contents, list) and contents:
            item = contents[0]
            if hasattr(item, "text"):
                try: return json.loads(item.text)
                except: return item.text
    if isinstance(result, (dict, list)): return result
    return result

if __name__ == "__main__":
    asyncio.run(main())
