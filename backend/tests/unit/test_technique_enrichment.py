"""M6.4 — technique-enrichment unit tests (live-name fallback).

The enrichment seam only runs live: offline/without a client it must return
exactly the static-table + bundle facts, and with a stub client it resolves
unknown techniques via ``get_mitre_technique`` with content-addressed caching.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

from app.services.technique_enrichment import (
    _bundle_technique_ids,
    enrich_technique_maps,
)
from app.services.mitre_meta import TECHNIQUE_NAMES, TTP_TACTICS

_BUNDLE = {
    "id": "TL-2026-1693",
    "ttps": ["T1027", "T1518.001", "T9999"],
    "techniques": [
        {"id": "T1027", "tactic": "defense-evasion", "name": "Obfuscated Files or Information"},
        {"id": "T1518.001", "tactic": "discovery"},
    ],
}


def test_bundle_technique_ids_collects_techniques_and_ttps():
    assert set(_bundle_technique_ids(_BUNDLE)) == {"T1027", "T1518.001", "T9999"}


async def test_offline_keeps_static_facts_without_client():
    """No client → deterministic static+bundle maps; unknown keeps id/""."""
    tactic_map, name_map = await enrich_technique_maps(_BUNDLE, client=None)
    assert tactic_map["T1027"] == "defense-evasion"
    assert name_map["T1027"] == "Obfuscated Files or Information"
    # T1518.001 not in static TECHNIQUE_NAMES, no bundle name → stays "".
    assert name_map["T1518.001"] == ""
    assert tactic_map["T1518.001"] == "discovery"
    # Unknown technique gets no fabricated value.
    assert name_map["T9999"] == ""


async def test_live_resolves_unknown_and_caches_content_addressed():
    """With a stub client, unknown techniques get their real name/tactic and
    the result is cached per technique id."""
    client = AsyncMock()

    async def fake_get(technique_id: str):
        if technique_id == "T1518.001":
            return {"name": "Software Discovery", "tactic": "discovery"}
        return None  # T9999 not known to the API either.

    client.get_mitre_technique = fake_get
    cache = AsyncMock()
    cache.get_technique.return_value = None

    tactic_map, name_map = await enrich_technique_maps(
        _BUNDLE, client=client, cache=cache
    )

    assert cache.get_technique.await_count == 2
    cache.put_technique.assert_awaited()
    assert name_map["T1518.001"] == "Software Discovery"
    assert tactic_map["T1518.001"] == "discovery"
    # Static/bundle facts untouched, unknown-with-no-lookup still empty.
    assert name_map["T1027"] == "Obfuscated Files or Information"
    assert name_map["T9999"] == ""


async def test_live_uses_cache_when_present():
    """Cache hit → no MCP call, quota saved."""
    client = AsyncMock()
    cache = AsyncMock()
    cache.get_technique.return_value = {"name": "Software Discovery", "tactic": "discovery"}

    tactic_map, name_map = await enrich_technique_maps(
        _BUNDLE, client=client, cache=cache
    )

    client.get_mitre_technique.assert_not_awaited()
    assert name_map["T1518.001"] == "Software Discovery"


async def test_live_lookup_failure_degrades_to_static():
    client = AsyncMock()
    client.get_mitre_technique.side_effect = RuntimeError("session lost")
    tactic_map, name_map = await enrich_technique_maps(_BUNDLE, client=client, cache=None)
    assert name_map["T1518.001"] == ""
    assert tactic_map["T1518.001"] == "discovery"


async def test_placeholder_name_does_not_mask_live_resolution():
    """A bundle whose ``name`` equals the technique id is a placeholder, not a
    fact — it must NOT suppress the live lookup (spec-review finding)."""
    bundle = {
        "id": "TL-2026-1693",
        "techniques": [{"id": "T1518.001", "name": "T1518.001", "tactic": "discovery"}],
    }
    client = AsyncMock()
    called: list[str] = []

    async def fake_get(technique_id: str):
        called.append(technique_id)
        return {"name": "Software Discovery", "tactic": "discovery"}

    client.get_mitre_technique = fake_get

    tactic_map, name_map = await enrich_technique_maps(bundle, client=client, cache=None)

    assert called == ["T1518.001"]
    assert name_map["T1518.001"] == "Software Discovery"
    assert tactic_map["T1518.001"] == "discovery"


async def test_curated_static_name_wins_over_bundle_name():
    """Static table is curated; a bundle-carried real name must not override it."""
    bundle = {
        "id": "TL-2026-1693",
        "techniques": [{"id": "T1082", "name": "Self Defensive Stuff", "tactic": "other"}],
    }
    tactic_map, name_map = await enrich_technique_maps(bundle, client=None)
    assert name_map["T1082"] == TECHNIQUE_NAMES["T1082"]
    assert name_map["T1082"] != "Self Defensive Stuff"
    assert tactic_map["T1082"] == TTP_TACTICS["T1082"]