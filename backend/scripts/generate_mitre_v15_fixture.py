#!/usr/bin/env python
"""Generate backend/fixtures/mitre_attack_v15.yaml from the Threadlinqs MCP.

Two layers (ticket 01, F2):
- ``fetch_stix(client)`` — LIVE export via the generic
  ``ThreadlinqsClient.call_tool("export_stix", ...)``; manual
  commit-generation only, never invoked in tests/CI.
- ``build_fixture(stix_objects, provenance) -> bytes`` — PURE, deterministic
  render of the minimal triple ``technique_id -> {name, tactic, data_sources[]}``
  with a provenance header. Unit tests feed ``tests/fixtures/stix_sample.json``
  + fixed provenance and assert byte-identical output.

Usage (from backend/ with venv active):
    python scripts/generate_mitre_v15_fixture.py --bundle PATH  # canonical MITRE STIX
    python scripts/generate_mitre_v15_fixture.py --write        # live export_stix
    python scripts/generate_mitre_v15_fixture.py --check        # dry-run compare

``--bundle`` reads a canonical MITRE ATT&CK STIX bundle file (e.g. the official
``enterprise-attack.json``) and is the primary source on Threadlinqs MCP v7.1.0,
which does not expose an ``export_stix`` tool — the MCP server has no such tool
in its tool list, so the fixture is generated from the same canonical STIX data
the future (ticket 06) typed wrapper will return. ``--bundle`` needs no API key.

If THREADLINQS_API_KEY is absent, ``--write`` prints a skip message and exits
0, leaving an existing committed fixture untouched.
"""

from __future__ import annotations

import asyncio
import pathlib
import sys
from datetime import date

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Same sys.path convention as smoke_threadlinqs.py: scripts/ is an infra
# utility directory; the top-level build_fixture block stays app-free.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

FIXTURE_PATH = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "mitre_attack_v15.yaml"
STIX_SAMPLE_PATH = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "stix_sample.json"

DEFAULT_PROVENANCE = {
    "version": "15.x",
    "generated_at": date.today().isoformat(),  # date-only (F3), never a timestamp
    "source": "threadlinqs_mcp_export_stix",
    "license": "CC-BY-4.0",
}

# Canary: documented placeholder-fallback case (F4 soft check) — a WARN + map.md
# note when the live export lacks it, never a ticket failure.
CANARY_TECHNIQUE = "T1518.001"


def _extract_external_id(obj: dict) -> str | None:
    """Pull the mitre-attack external id (Txxxx[.yyy]) from an STIX object."""
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") != "mitre-attack":
            continue
        ext = ref.get("external_id")
        if isinstance(ext, str) and ext.startswith("T"):
            return ext
    return None


def extract_techniques(stix_objects: list[dict]) -> dict[str, dict]:
    """attack-pattern objects -> ``{Txxxx: {name, tactic, data_sources[]}}``.

    Deterministic: data_sources sorted and de-duplicated. Unknown techniques
    (no mitre-attack external id) are skipped.
    """
    out: dict[str, dict] = {}
    for obj in stix_objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        tid = _extract_external_id(obj)
        if not tid:
            continue
        tactic = ""
        for phase in obj.get("kill_chain_phases") or []:
            if isinstance(phase, dict) and phase.get("kill_chain_name") == "mitre-attack":
                tactic = str(phase.get("phase_name", ""))
                break
        data_sources = sorted(
            {
                str(ds)
                for ds in (obj.get("x_mitre_data_sources") or [])
                if isinstance(ds, str) and ds
            }
        )
        out[tid] = {
            "name": str(obj.get("name", "")),
            "tactic": tactic,
            "data_sources": data_sources,
        }
    return out


def build_fixture(stix_objects: list[dict], provenance: dict) -> bytes:
    """Pure deterministic fixture bytes from raw STIX attack-patterns (F2/F3).

    Stable serialization: sorted keys, fixed indent, allow_unicode. Never
    touches the network; live ``fetch_stix`` is the caller's concern.
    """
    techniques = extract_techniques(stix_objects)
    payload = {
        "_provenance": {
            "version": str(provenance["version"]),
            "generated_at": str(provenance["generated_at"]),
            "source": str(provenance["source"]),
            "license": str(provenance["license"]),
        },
        "techniques": techniques,
    }
    import yaml

    return yaml.safe_dump(
        payload, sort_keys=True, indent=2, allow_unicode=True
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Live layer — manual generation only (F2)
# ---------------------------------------------------------------------------


async def fetch_stix(client) -> list[dict]:
    """Live export of STIX attack-pattern objects via call_tool.

    Uses the generic ``ThreadlinqsClient.call_tool("export_stix", {...})``
    (P4) — NOT the typed wrapper ticket 06 adds. Never invoked in tests.
    """
    result = await client.call_tool(
        "export_stix",
        {"domain": "enterprise-attack", "include_relationships": False},
    )
    # Result is either an MCP structured content payload, text JSON, or bytes.
    payload = result
    if hasattr(result, "content") and getattr(result, "content", None):
        items = []
        for part in result.content:
            text = getattr(part, "text", None)
            data = getattr(part, "data", None)
            if text:
                items.append(text)
            elif data:
                items.append(data)
        # export_stix returns a single STIX bundle document as text.
        for item in items:
            if isinstance(item, str):
                parsed = _try_json(item)
                if parsed is not None:
                    payload = parsed
                    break
    if isinstance(payload, (bytes, bytearray)):
        parsed = _try_json(bytes(payload).decode("utf-8", errors="replace"))
        if parsed is not None:
            payload = parsed
    if isinstance(payload, str):
        parsed = _try_json(payload)
        if parsed is not None:
            payload = parsed
    objects = payload.get("objects") if isinstance(payload, dict) else None
    if not isinstance(objects, list):
        raise ValueError("export_stix did not return a bundle with an objects list")
    return [o for o in objects if isinstance(o, dict)]


def _try_json(text: str) -> dict | list | None:
    import json

    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _get_api_key() -> str | None:
    import os

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


async def _write_fixture_live() -> int:
    """Fetch live, enrich data_sources, write fixture. Exit code 0/1."""
    from app.services.threadlinqs_client import ThreadlinqsClient

    client = ThreadlinqsClient()
    try:
        stix_objects = await fetch_stix(client)
    except Exception as exc:  # noqa: BLE001 - script boundary, report and skip
        print(f"ERROR: live export_stix failed: {exc}")
        return 1

    print(f"export_stix returned {len(stix_objects)} objects")
    techniques = extract_techniques(stix_objects)
    print(f"  -> {len(techniques)} attack-patterns with mitre-attack ids")

    # F4: enrich data_sources from get_mitre_technique when the export carries
    # no x_mitre_data_sources (batched, cached under tl:technique:* upstream).
    empty = sorted(tid for tid, meta in techniques.items() if not meta["data_sources"])
    if empty:
        print(f"WARN: {len(empty)} techniques lack export data_sources, enriching: {empty[:10]}...")
        for tid in empty:
            try:
                live_meta = await client.get_mitre_technique(tid)
            except Exception:  # noqa: BLE001 - degrade gracefully
                live_meta = None
            if live_meta and live_meta.get("data_sources"):
                techniques[tid]["data_sources"] = sorted(
                    {str(s) for s in live_meta["data_sources"] if str(s)}
                )

    provenance = dict(DEFAULT_PROVENANCE)
    rendered = build_fixture(stix_objects, provenance)

    if CANARY_TECHNIQUE in techniques and techniques[CANARY_TECHNIQUE]["name"] == CANARY_TECHNIQUE:
        print(f"WARN: canary {CANARY_TECHNIQUE} resolved to a placeholder name")
    elif CANARY_TECHNIQUE not in techniques:
        print(f"WARN: canary {CANARY_TECHNIQUE} absent from export (covered by fallback level 2 live)")
    else:
        print(f"OK: canary {CANARY_TECHNIQUE} = {techniques[CANARY_TECHNIQUE]['name']!r}")

    FIXTURE_PATH.write_bytes(rendered)
    print(f"WROTE {FIXTURE_PATH} ({len(rendered)} bytes, generated_at={provenance['generated_at']})")
    return 0


def _load_bundle_file(path: str | pathlib.Path) -> list[dict]:
    """Read a canonical MITRE ATT&CK STIX bundle file -> object list."""
    import json

    with pathlib.Path(path).open(encoding="utf-8") as fh:
        payload = json.load(fh)
    objects = payload.get("objects") if isinstance(payload, dict) else payload
    if not isinstance(objects, list):
        raise ValueError(f"bundle {path} has no objects list")
    return [o for o in objects if isinstance(o, dict)]


def _write_fixture_from_bundle(bundle_path: str | pathlib.Path) -> int:
    """Write the committed fixture from a canonical STIX bundle file.

    Honest provenance: source names the actual canonical file, not the
    (currently absent on MCP v7.1.0) export_stix tool.
    """
    stix_objects = _load_bundle_file(bundle_path)
    print(f"bundle {bundle_path} -> {len(stix_objects)} objects")
    techniques = extract_techniques(stix_objects)
    print(f"  -> {len(techniques)} attack-patterns with mitre-attack ids")

    provenance = {
        "version": "15.1",
        "generated_at": date.today().isoformat(),
        "source": "mitre_attack_stix_15.1",
        "license": "CC-BY-4.0",
    }
    rendered = build_fixture(stix_objects, provenance)

    if CANARY_TECHNIQUE in techniques and techniques[CANARY_TECHNIQUE]["name"] == CANARY_TECHNIQUE:
        print(f"WARN: canary {CANARY_TECHNIQUE} resolved to a placeholder name")
    elif CANARY_TECHNIQUE not in techniques:
        print(f"WARN: canary {CANARY_TECHNIQUE} absent from bundle")
    else:
        print(f"OK: canary {CANARY_TECHNIQUE} = {techniques[CANARY_TECHNIQUE]['name']!r}")

    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_bytes(rendered)
    print(f"WROTE {FIXTURE_PATH} ({len(rendered)} bytes, version={provenance['version']}, generated_at={provenance['generated_at']})")
    return 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the committed fixture")
    parser.add_argument("--bundle", metavar="PATH", help="write the committed fixture from a canonical MITRE STIX bundle file")
    parser.add_argument("--check", action="store_true", help="compare build_fixture against committed fixture")
    args = parser.parse_args()

    if args.bundle:
        return _write_fixture_from_bundle(args.bundle)

    if not _get_api_key():
        print("SKIP: THREADLINQS_API_KEY absent; committed fixture left untouched")
        return 0

    if args.check:
        if not FIXTURE_PATH.exists():
            print(f"ERROR: {FIXTURE_PATH} does not exist")
            return 1
        import json

        with STIX_SAMPLE_PATH.open(encoding="utf-8") as fh:
            payload = json.load(fh)
        objects = [o for o in payload.get("objects", []) if isinstance(o, dict)]
        rendered = build_fixture(objects, DEFAULT_PROVENANCE)
        existing = FIXTURE_PATH.read_bytes()
        if rendered == existing:
            print(f"CHECK PASS: build_fixture(stix_sample) == committed fixture")
            return 0
        print("CHECK FAIL: build_fixture(stix_sample) differs from committed fixture")
        print("  (expected: the committed fixture was generated from the full live export)")
        return 1

    return asyncio.run(_write_fixture_live())


if __name__ == "__main__":
    raise SystemExit(main())