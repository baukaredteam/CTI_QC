"""Content-addressed Redis cache for Threadlinqs bundles.

Each bundle is fetched once (keyed by SHA-256 of bundle ID) and scored
per tenant locally. This avoids redundant MCP calls for the same threat
intelligence across multiple tenants.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Default TTL: 24 hours
DEFAULT_CACHE_TTL_HOURS = 24


def _cache_key(bundle_id: str) -> str:
    """Generate a content-addressed cache key from bundle ID."""
    digest = hashlib.sha256(bundle_id.encode("utf-8")).hexdigest()
    return f"tl:bundle:{digest}"


def _technique_cache_key(technique_id: str) -> str:
    """Content-addressed cache key for one MITRE technique id."""
    digest = hashlib.sha256(technique_id.encode("utf-8")).hexdigest()
    return f"tl:technique:{digest}"


class ThreadlinqsCache:
    """Content-addressed cache backed by Redis.

    Args:
        redis: An async Redis client instance (aioredis-compatible).
        ttl_hours: Hours to keep cached bundles.
    """

    def __init__(self, redis: Any, ttl_hours: int = DEFAULT_CACHE_TTL_HOURS) -> None:
        self._redis = redis
        self._ttl_seconds = ttl_hours * 3600

    async def get(self, bundle_id: str) -> dict[str, Any] | None:
        """Retrieve a cached bundle by its ID.

        Returns:
            The parsed bundle dict, or None if not cached.
        """
        key = _cache_key(bundle_id)
        try:
            raw = await self._redis.get(key)
        except Exception:
            logger.warning("Redis GET failed for key %s", key, exc_info=True)
            return None

        if raw is None:
            return None

        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Corrupt cache entry for key %s, deleting", key)
            try:
                await self._redis.delete(key)
            except Exception:
                pass
            return None

    async def put(self, bundle_id: str, bundle: dict[str, Any]) -> None:
        """Store a bundle in the cache.

        Args:
            bundle_id: The unique bundle identifier.
            bundle: The full bundle dict to cache.
        """
        key = _cache_key(bundle_id)
        try:
            serialized = json.dumps(bundle, default=str)
            await self._redis.set(key, serialized, ex=self._ttl_seconds)
        except Exception:
            logger.warning("Redis SET failed for key %s", key, exc_info=True)

    async def has(self, bundle_id: str) -> bool:
        """Check if a bundle is cached without retrieving it."""
        key = _cache_key(bundle_id)
        try:
            return bool(await self._redis.exists(key))
        except Exception:
            logger.warning("Redis EXISTS failed for key %s", key, exc_info=True)
            return False

    async def invalidate(self, bundle_id: str) -> None:
        """Remove a bundle from the cache."""
        key = _cache_key(bundle_id)
        try:
            await self._redis.delete(key)
        except Exception:
            logger.warning("Redis DELETE failed for key %s", key, exc_info=True)

    async def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Retrieve cached MITRE metadata for a technique id."""
        key = _technique_cache_key(technique_id)
        try:
            raw = await self._redis.get(key)
        except Exception:
            logger.warning("Redis GET failed for key %s", key, exc_info=True)
            return None

        if raw is None:
            return None

        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Corrupt cache entry for key %s, deleting", key)
            try:
                await self._redis.delete(key)
            except Exception:
                pass
            return None

    async def put_technique(self, technique_id: str, meta: dict[str, Any]) -> None:
        """Store MITRE metadata for a technique id (content-addressed)."""
        key = _technique_cache_key(technique_id)
        try:
            serialized = json.dumps(meta, default=str)
            await self._redis.set(key, serialized, ex=self._ttl_seconds)
        except Exception:
            logger.warning("Redis SET failed for key %s", key, exc_info=True)
