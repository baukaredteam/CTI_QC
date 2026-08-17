"""09.1 — ThreadlinqsCache TTL separation (Ticket 09.1) test suite.

Pure-unit, no real Redis (``test_mcp_enricher.py`` style): a minimal fake
async redis records ``set`` calls with their ``ex`` TTL, so the bundle vs
technique TTL contract is asserted directly at the cache seam.

Contract (see ``09.1-technique-cache-ttl.spec.md``):

- bundle cache default TTL stays 24 hours (``tl:bundle:<sha256>``);
- technique cache default TTL becomes 7 days (``tl:technique:<sha256>``);
- custom ``ttl_hours`` drives bundle entries only; custom
  ``technique_ttl_hours`` drives technique entries only; the two may differ
  in one instance;
- malformed Redis JSON on a technique key returns ``None`` and follows the
  existing safe-delete behavior.

Expected values below are spec literals (``7 * 24 * 3600``, ``24 * 3600``,
...), never recomputed from the implementation — a tautological assertion is
a failure of this suite.
"""

from __future__ import annotations

import hashlib

from app.services.threadlinqs_cache import ThreadlinqsCache, _technique_cache_key

_SEVEN_DAYS_S = 7 * 24 * 3600
_TWENTY_FOUR_HOURS_S = 24 * 3600


class _FakeRedis:
    """Minimal async Redis stand-in that records ``set`` calls with TTL."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.sets: list[tuple[str, str, int | None]] = []

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.sets.append((key, value, ex))
        self.store[key] = value

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)

    async def exists(self, key: str) -> bool:
        return key in self.store


# ---------------------------------------------------------------------------
# Default TTL separation (spec tests 1 & 2)
# ---------------------------------------------------------------------------


async def test_default_put_technique_writes_seven_day_ttl():
    redis = _FakeRedis()
    cache = ThreadlinqsCache(redis)

    await cache.put_technique("T1059.001", {"name": "PowerShell"})

    assert len(redis.sets) == 1
    _key, _value, ex = redis.sets[0]
    assert ex == _SEVEN_DAYS_S


async def test_default_bundle_put_keeps_twenty_four_hour_ttl():
    redis = _FakeRedis()
    cache = ThreadlinqsCache(redis)

    await cache.put("TL-2026-001", {"id": "TL-2026-001"})

    assert len(redis.sets) == 1
    _key, _value, ex = redis.sets[0]
    assert ex == _TWENTY_FOUR_HOURS_S


# ---------------------------------------------------------------------------
# Custom TTLs (spec tests 3, 4, 5)
# ---------------------------------------------------------------------------


async def test_custom_ttl_hours_changes_bundle_ttl():
    redis = _FakeRedis()
    cache = ThreadlinqsCache(redis, ttl_hours=12)

    await cache.put("TL-2026-001", {"id": "TL-2026-001"})

    assert len(redis.sets) == 1
    _key, _value, ex = redis.sets[0]
    assert ex == 12 * 3600


async def test_custom_technique_ttl_hours_changes_technique_ttl():
    redis = _FakeRedis()
    cache = ThreadlinqsCache(redis, technique_ttl_hours=48)

    await cache.put_technique("T1059.001", {"name": "PowerShell"})

    assert len(redis.sets) == 1
    _key, _value, ex = redis.sets[0]
    assert ex == 48 * 3600


async def test_bundle_and_technique_ttl_can_differ_in_one_instance():
    redis = _FakeRedis()
    cache = ThreadlinqsCache(redis, ttl_hours=12, technique_ttl_hours=48)

    await cache.put("TL-2026-001", {"id": "TL-2026-001"})
    await cache.put_technique("T1059.001", {"name": "PowerShell"})

    assert [ex for _key, _value, ex in redis.sets] == [12 * 3600, 48 * 3600]


# ---------------------------------------------------------------------------
# Key formats stay content-addressed (spec tests 6 & 7)
# ---------------------------------------------------------------------------


async def test_technique_key_stays_content_addressed():
    redis = _FakeRedis()
    cache = ThreadlinqsCache(redis)

    await cache.put_technique("T1059.001", {"name": "PowerShell"})

    key = redis.sets[0][0]
    assert key.startswith("tl:technique:")
    assert key == _technique_cache_key("T1059.001")
    assert _technique_cache_key("T1059.001") != _technique_cache_key("T1027")


async def test_bundle_key_stays_content_addressed():
    redis = _FakeRedis()
    cache = ThreadlinqsCache(redis)

    await cache.put("TL-2026-001", {"id": "TL-2026-001"})

    key = redis.sets[0][0]
    digest = hashlib.sha256(b"TL-2026-001").hexdigest()
    assert key == f"tl:bundle:{digest}"


# ---------------------------------------------------------------------------
# Degraded entries (spec test 8)
# ---------------------------------------------------------------------------


async def test_malformed_technique_entry_returns_none_and_deletes():
    redis = _FakeRedis()
    key = _technique_cache_key("T1059.001")
    redis.store[key] = "{not-json"

    cache = ThreadlinqsCache(redis)
    result = await cache.get_technique("T1059.001")

    assert result is None
    assert key not in redis.store  # existing safe-delete behavior preserved
