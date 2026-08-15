"""M6.4 — live technique-name/tactic enrichment.

The static ATT&CK tables in ``mitre_meta`` only cover curated techniques;
live headlines reference many more. For those, the scanner resolves the real
name/tactic from Threadlinqs ``get_mitre_technique`` and caches the result
content-addressed in ``threadlinqs_cache`` so repeated scans reuse quota.

This module is live-only, deterministic-once-fetched: offline/tests keep the
static tables + id/"" fallback inside the pure generator/summary — they never
touch it.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Sequence

from app.services.mitre_meta import TECHNIQUE_NAMES, TTP_TACTICS

logger = logging.getLogger(__name__)


def _bundle_technique_ids(bundle: Mapping[str, Any]) -> list[str]:
    """Every technique id the bundle mentions (techniques + ttps lists)."""
    ids: set[str] = set()

    techniques = bundle.get("techniques")
    if isinstance(techniques, list):
        for item in techniques:
            if not isinstance(item, Mapping):
                continue
            tid = str(item.get("id") or item.get("technique_id") or "").strip().upper()
            if tid:
                ids.add(tid)

    for key in ("ttps", "mitre_technique_ids", "technique_ids"):
        values = bundle.get(key)
        if isinstance(values, list):
            for value in values:
                tid = str(value or "").strip().upper()
                if tid:
                    ids.add(tid)

    return sorted(ids)


def _is_placeholder_name(technique_id: str, name: str) -> bool:
    """A bundle entry whose ``name`` is just the technique id is a placeholder,
    not a real ATT&CK name — treat it as unknown so static/live resolution wins."""
    return not str(name).strip() or str(name).strip().upper() == str(technique_id).strip().upper()


def _bundle_names(bundle: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """Bundle-carried (tactic_map, name_map) from the ``techniques`` list.

    Placeholder names equal to the technique id are dropped so they never mask
    static-table or live-resolved names."""
    tactic_map: dict[str, str] = {}
    name_map: dict[str, str] = {}
    techniques = bundle.get("techniques")
    if isinstance(techniques, list):
        for item in techniques:
            if not isinstance(item, Mapping):
                continue
            tid = str(item.get("id") or item.get("technique_id") or "").strip().upper()
            tactic = str(item.get("tactic") or item.get("tactic_name") or "").strip()
            name = str(item.get("name") or item.get("technique_name") or "").strip()
            if tid:
                if tactic:
                    tactic_map[tid] = tactic
                if name and not _is_placeholder_name(tid, name):
                    name_map[tid] = name
    return tactic_map, name_map


def _base_maps(bundle: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """Choreograph static + bundle facts into the starting tactic/name maps.

    Curated static names/tactics win over bundle-carried ones; bundle facts fill
    gaps only. Never the other way around (review finding)."""
    bundle_tactics, bundle_names = _bundle_names(bundle)
    ids = _bundle_technique_ids(bundle)
    tactic_map = {tid: TTP_TACTICS.get(tid, "") for tid in ids}
    name_map = {tid: TECHNIQUE_NAMES.get(tid, "") for tid in ids}
    for tid in ids:
        if not tactic_map.get(tid) and bundle_tactics.get(tid):
            tactic_map[tid] = bundle_tactics[tid]
        if not name_map.get(tid) and bundle_names.get(tid):
            name_map[tid] = bundle_names[tid]
    return tactic_map, name_map


async def enrich_technique_maps(
    bundle: Mapping[str, Any],
    *,
    technique_ids: Sequence[str] | None = None,
    client: Any = None,
    cache: Any = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Return enriched ``(tactic_map, name_map)``: bundle + static + live.

    With ``client`` (a ThreadlinqsClient) and optional ``cache``, unknown
    techniques — those with no bundle name and no static name — are looked up
    via ``get_mitre_technique`` and cached content-addressed. Without a client
    it stays fully offline (static + bundle facts only), which is the
    deterministic fallback every test/offline path relies on.
    """
    tactic_map, name_map = _base_maps(bundle)
    candidates = list(technique_ids) if technique_ids else _bundle_technique_ids(bundle)
    # A technique needs enrichment only when it has neither static nor bundle name.
    unknown = [tid for tid in candidates if not name_map.get(tid)]
    if not unknown or client is None:
        return tactic_map, name_map

    for tid in unknown:
        meta: dict[str, Any] | None = None
        if cache is not None:
            try:
                meta = await cache.get_technique(tid)
            except Exception:
                meta = None
        if meta is None:
            try:
                meta = await client.get_mitre_technique(tid)
            except Exception:
                logger.warning("get_mitre_technique failed for %s", tid, exc_info=True)
                meta = None
            if meta and cache is not None:
                try:
                    await cache.put_technique(tid, meta)
                except Exception:
                    pass
        if not meta:
            continue
        name = str(meta.get("name") or "").strip()
        tactic = str(meta.get("tactic") or "").strip()
        if not name_map.get(tid) and name:
            name_map[tid] = name
        if not tactic_map.get(tid) and tactic:
            tactic_map[tid] = tactic
    return tactic_map, name_map