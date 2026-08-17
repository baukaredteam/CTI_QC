"""M6.4 — Hypothesis feed scanner (Celery orchestration).

Periodic worker that turns recently active threat bundles into persistent
hunt hypotheses per tenant, using the pure generator (no LLM, no DB). The
async core ``scan_feed`` is testable offline: fetchers are injected, and when
the live Threadlinqs integration is disabled the scan degrades to the exact
canonical offline bundle the management seam uses — so the deterministic path
stays byte-identical live and offline.

Status: every generated hypothesis starts ``proposed``; analysts route them to
``validated`` / ``rejected`` via the API/page.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.core.config import settings
from app.services.hypothesis_generator import generate_hypotheses
from app.services.hypothesis_store import add_many, save_to_file
from app.services.management_service import DEFAULT_THREAT_ID, load_flat_bundle
from app.services.rules_parser import Rule, parse_rules_file
from app.services.tenants_provider import all_tenants
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 7


def _fixtures_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "fixtures"


def _fixture_rules() -> Path:
    return _fixtures_dir() / "full_rules85.yaml"


async def _recent_threat_ids(
    *, fetch: Any, limit: int = DEFAULT_LIMIT
) -> list[str]:
    """Return threat ids from the injected fetcher.

    The fetcher is an async callable mimicking ``get_recent_threats``; it
    returns a list of threat records (dicts or plain ids). An unfillable live
    fetch degrades to the canonical offline id so the deterministic path runs.
    """
    try:
        recent = await fetch(limit)
    except Exception:
        logger.warning("Recent-threats fetch failed; degrading to %s", DEFAULT_THREAT_ID, exc_info=True)
        return [DEFAULT_THREAT_ID]

    ids: list[str] = []
    for item in recent if isinstance(recent, list) else [recent]:
        if isinstance(item, Mapping):
            tid = item.get("threat_id") or item.get("id") or item.get("bundle_id")
        else:
            tid = item
        if tid and str(tid).strip() and str(tid) not in ids:
            ids.append(str(tid).strip())
    return ids or [DEFAULT_THREAT_ID]


def _tactic_map(bundle: Mapping[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in bundle.get("techniques") if isinstance(bundle.get("techniques"), list) else []:
        if not isinstance(item, Mapping):
            continue
        tid = str(item.get("id") or item.get("technique_id") or "").upper().strip()
        tactic = str(item.get("tactic") or item.get("tactic_name") or "").strip()
        if tid and tactic:
            mapping[tid] = tactic
    return mapping


async def _bundle_loader(threat_id: str) -> dict[str, Any]:
    return await load_flat_bundle(threat_id)


async def live_recent_threat_ids(limit: int = DEFAULT_LIMIT) -> list[str]:
    """Return recent threat ids from Threadlinqs ``get_recent_threats(limit)``.

    On any failure (session, rate limit, circuit) it degrades to the canonical
    single default threat so the deterministic path still runs.
    """
    from app.services.threadlinqs_client import ThreadlinqsClient

    client = ThreadlinqsClient()
    try:
        await client.connect()
        recent = await client.get_recent_threats(limit)
    except Exception:
        logger.warning("Live recent-threat fetch failed; degrading to %s", DEFAULT_THREAT_ID, exc_info=True)
        return [DEFAULT_THREAT_ID]
    finally:
        await client.disconnect()

    ids: list[str] = []
    for item in recent:
        if isinstance(item, Mapping):
            tid = item.get("threat_id") or item.get("id") or item.get("bundle_id")
        else:
            tid = item
        if tid and str(tid).strip() and str(tid) not in ids:
            ids.append(str(tid).strip())
    return ids or [DEFAULT_THREAT_ID]


async def scan_feed(
    *,
    fetch_recent: Any | None = None,
    bundle_loader: Any | None = None,
    rules_path: Path | None = None,
    limit: int = DEFAULT_LIMIT,
    tenants: Sequence[Mapping[str, Any]] | None = None,
    store_path: Path | None = None,
    min_relevance: float | None = None,
    enrich: bool = False,
) -> dict[str, Any]:
    """Scan recent threats and persist generated hypotheses.

    Args:
        fetch_recent: async ``callable(limit) -> list[bundle-id dicts]``.
        bundle_loader: async ``callable(threat_id) -> flat bundle dict``.
        rules_path: rules fixture to feed the generator.
        limit: how many recent threats to scan.
        tenants: tenant profiles to seed (defaults to all inline tenants).
        store_path: where to persist hypotheses (default fixture JSON).
        min_relevance: relevance gate for a threat × tenant pair (M6.4 STEP 4).
        enrich: when the live Threadlinqs integration is enabled, resolve
            technique names/tactics for techniques missing from the static
            table via ``get_mitre_technique`` (cached). Pure offline scans
            (tests, disabled integration) stay on the static table.

    Returns:
        Deterministic run report: threats scanned, generated, skipped.
    """
    rules = parse_rules_file(rules_path or _fixture_rules()).rules
    tenant_rows = list(tenants) if tenants is not None else all_tenants()
    loader = bundle_loader if bundle_loader is not None else _bundle_loader

    async def _fetch_recent(_limit: int) -> list[dict[str, Any]]:
        if fetch_recent is not None:
            return await fetch_recent(_limit)
        return [{"threat_id": DEFAULT_THREAT_ID}]

    threat_ids = await _recent_threat_ids(fetch=_fetch_recent, limit=limit)

    live = bool(settings.threadlinqs_enabled and enrich)
    client = None
    cache = None
    if live:
        from app.services.technique_enrichment import enrich_technique_maps
        from app.services.threadlinqs_cache import ThreadlinqsCache
        from app.services.threadlinqs_client import ThreadlinqsClient
        from app.services.threadlinqs_mcp_enricher import (
            enrich_hypotheses,
            enrich_predictions,
        )

        client = ThreadlinqsClient(settings.threadlinqs_api_key)
        if settings.redis_url:
            try:
                import redis as _redis

                redis_conn = _redis.asyncio.from_url(settings.redis_url)
                cache = ThreadlinqsCache(redis_conn)
            except Exception:
                cache = None

    generated = 0
    skipped = 0
    for threat_id in threat_ids:
        try:
            bundle = await loader(threat_id)
        except Exception:
            logger.warning("Bundle failed for %s; skipping", threat_id, exc_info=True)
            skipped += 1
            continue
        flat = bundle if isinstance(bundle, dict) else dict(bundle or {})
        tactic_map = _tactic_map(flat)
        technique_names: dict[str, str] | None = None
        if live:
            try:
                tactic_map, technique_names = await enrich_technique_maps(
                    flat,
                    client=client,
                    cache=cache,
                )
            except Exception:
                logger.warning("Technique enrichment failed for %s; using static", threat_id, exc_info=True)
        for tenant in tenant_rows:
            hypotheses = generate_hypotheses(
                threat_id=threat_id,
                bundle=flat,
                tenant=tenant,
                rules=rules,
                tactic_map=tactic_map,
                technique_names=technique_names,
                min_relevance=min_relevance,
            )
            # Ticket 08/09B (M6.4): live scans enrich from the MCP bundle seam
            # and predict next techniques; both share one client + cache, and
            # both are passthrough when the MCP is unavailable. Offline scans
            # (client None) stay byte-identical to the pure path.
            if client is not None:
                hypotheses = await enrich_hypotheses(hypotheses, client)
                hypotheses = await enrich_predictions(hypotheses, client, cache)
            generated += add_many(hypotheses)
            logger.info(
                "Scanned threat %s, generated %d hypotheses for tenant %s",
                threat_id,
                len(hypotheses),
                tenant.get("name") or tenant.get("id") or "?",
            )
    save_to_file(store_path)
    return {"threats_scanned": len(threat_ids), "generated": generated, "skipped": skipped}


@celery_app.task(
    bind=True,
    name="feed_scanner.scan",
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=3,
    default_retry_delay=15,
)
def scan_task(self, **kwargs: Any) -> dict[str, Any]:
    """Celery entry: run the async scanner, guarded by the feature flag."""
    if not settings.hypothesis_enabled:
        return {"status": "disabled"}
    return asyncio.run(scan_feed(**kwargs))