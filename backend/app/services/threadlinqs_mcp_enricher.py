"""M6.4 — MCP bundle enricher (Ticket 08).

One new enrichment seam: decorate Hypotheses with related threats, adversary
playbooks, and infrastructure pivots from ``get_threat_hunting_bundle``.

Contract:
- pure: returns NEW ``Hypothesis`` objects via ``model_copy``; the input list
  is never mutated;
- batched: exactly one ``get_threat_hunting_bundle(threat_id,
  simulation_limit=3, pivot_limit=25)`` call per unique ``threat_id``; results
  map back onto the hypotheses by ``threat_id``;
- pass-through: any MCP unavailability (open breaker, integration disabled,
  timeout, malformed/empty envelope, or a missing enrichment block) leaves the
  affected hypotheses untouched (same objects), never an exception — the hunt
  pipeline never breaks when Threadlinqs is down.

Extraction reuses ``normalize_bundle`` (Ticket 07) so the envelope-reading and
text-drain logic lives in exactly one place. No settings are read here: the
client itself degrades to ``{}`` when disabled/breaker/rate-limited, which the
enrichment-keys gate below treats as pass-through.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Any

from mcp.shared.exceptions import McpError

from app.schemas.hypothesis import Hypothesis
from app.services.circuit_breaker import CircuitOpenError
from app.services.rate_limiter import RateLimitExceeded
from app.services.threadlinqs_client import ThreadlinqsClientError
from app.services.threadlinqs_normalizer import normalize_bundle

# Integration failures a live client may still surface; everything else is a
# programming error and must propagate. Mirrors the client's own degradation:
# these never break the hunt pipeline.
_INTEGRATION_ERRORS: tuple[type[BaseException], ...] = (
    ThreadlinqsClientError,
    CircuitOpenError,
    RateLimitExceeded,
    asyncio.TimeoutError,
    McpError,
)

# Same envelope keys the normalizer drains (depth-1, with a ``data`` fallback).
_ENRICHMENT_KEYS: tuple[str, ...] = ("similar_threats", "simulations", "infrastructure_pivots")

_PLAYBOOK_PREFIX = "adversary playbooks: "


def _threat_id(h: Hypothesis) -> str:
    return str(getattr(h, "threat_id", "") or "")


def _has_enrichment_keys(bundle: Mapping[str, Any]) -> bool:
    """True when any enrichment block is present at depth-1 or under ``data``.

    Mirrors the normalizer's own envelope fallback so pass-through and
    extraction agree on what an "enrichable" bundle is. An empty ``{}`` — the
    client's degraded-response shape — fails the gate, correctly.
    """
    for key in _ENRICHMENT_KEYS:
        if bundle.get(key) is not None:
            return True
    data = bundle.get("data")
    if isinstance(data, Mapping):
        for key in _ENRICHMENT_KEYS:
            if data.get(key) is not None:
                return True
    return False


def _enrich_expected_evidence(text: str, playbooks: Sequence[str]) -> str:
    """Append the adversary-playbook phrase once; idempotent on re-entry."""
    if not playbooks:
        return text
    if _PLAYBOOK_PREFIX in text:
        return text
    return f"{text} {_PLAYBOOK_PREFIX}{', '.join(str(p) for p in playbooks)}."


def _enriched(h: Hypothesis, bundle: Mapping[str, Any]) -> Hypothesis:
    """Return an enriched copy, or ``h`` itself when nothing new was carried."""
    normalized = normalize_bundle(dict(bundle))
    playbooks = list(getattr(normalized, "adversary_playbooks", []) or [])
    related = list(getattr(normalized, "related_threats", []) or [])
    pivots = list(getattr(normalized, "infrastructure_pivots", []) or [])
    if not (playbooks or related or pivots):
        return h
    return h.model_copy(
        update={
            "adversary_playbooks": playbooks,
            "related_threats": related,
            "infrastructure_pivots": pivots,
            "expected_evidence_ru": _enrich_expected_evidence(h.expected_evidence_ru, playbooks),
        }
    )


async def _fetch_bundle(fetch: Any, threat_id: str) -> dict[str, Any] | None:
    try:
        bundle = await fetch(threat_id, simulation_limit=3, pivot_limit=25)
    except _INTEGRATION_ERRORS:
        return None
    if isinstance(bundle, dict) and _has_enrichment_keys(bundle):
        return bundle
    return None


async def enrich_hypotheses(hypotheses, client) -> list[Hypothesis]:
    """Decorate hypotheses with MCP bundle facts; pass-through when degraded.

    One ``get_threat_hunting_bundle(threat_id, simulation_limit=3,
    pivot_limit=25)`` call per unique threat_id (first-seen order), results
    mapped back by threat_id. Hypotheses whose envelope is unavailable keep
    their exact original objects; when nothing could be enriched the input
    list itself is returned (same object, same elements).
    """
    rows = list(hypotheses)
    if not rows:
        return hypotheses

    fetch = getattr(client, "get_threat_hunting_bundle", None)
    if not callable(fetch):
        return hypotheses

    threat_ids = [tid for tid in dict.fromkeys(_threat_id(h) for h in rows) if tid]
    envelopes: dict[str, dict[str, Any]] = {}
    for tid in threat_ids:
        bundle = await _fetch_bundle(fetch, tid)
        if bundle is not None:
            envelopes[tid] = bundle

    if not envelopes:
        return hypotheses

    out: list[Hypothesis] = []
    changed = False
    for h in rows:
        bundle = envelopes.get(_threat_id(h))
        if bundle is None:
            out.append(h)
            continue
        enriched = _enriched(h, bundle)
        if enriched is not h:
            changed = True
        out.append(enriched)

    return out if changed else hypotheses