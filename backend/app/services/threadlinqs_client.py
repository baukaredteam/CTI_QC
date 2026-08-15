"""Threadlinqs MCP client — single long-lived stdio session.

Uses the official mcp Python SDK. Spawns `npx intelthreadlinqs-mcp` ONCE,
performs the initialize handshake, and reuses the session. Reconnects on
session drop. Never spawns npx per call.

Decorated with circuit breaker and rate limiter.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from app.services.circuit_breaker import CircuitBreaker, CircuitOpenError
from app.services.rate_limiter import DailyRateLimiter, RateLimitExceeded

logger = logging.getLogger(__name__)

# Circuit breaker: 3 consecutive failures → open for 60s
_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)


def _parse_tool_result(result: Any) -> Any:
    """Parse an MCP call_tool result into a plain object (JSON when possible)."""
    if hasattr(result, "content"):
        contents = result.content
        if isinstance(contents, list) and contents:
            item = contents[0]
            text = getattr(item, "text", None)
            if text is not None:
                try:
                    return json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    return text
            return item
    if isinstance(result, str):
        try:
            return json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return result
    return result

# Rate limiter: 5000 calls/day (Purple tier)
_rate_limiter = DailyRateLimiter(daily_limit=5000)


class ThreadlinqsClientError(Exception):
    """Base error for Threadlinqs client operations."""


class ThreadlinqsSessionError(ThreadlinqsClientError):
    """Raised when the MCP session cannot be established or is lost."""


class ThreadlinqsClient:
    """Long-lived MCP client for the Threadlinqs intelligence feed.

    Manages a single stdio session to `npx intelthreadlinqs-mcp`.
    Performs initialize handshake on first connect and reconnects
    automatically on session failures.

    Args:
        api_key: Threadlinqs API key. Falls back to env var THREADLINQS_API_KEY.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or self._key_from_settings() or os.environ.get("THREADLINQS_API_KEY", "")
        self._session: ClientSession | None = None
        self._stdio_context: Any = None
        self._read_write_context: Any = None
        self._initialized = False
        self._lock = asyncio.Lock()

    @property
    def is_connected(self) -> bool:
        return self._session is not None and self._initialized

    async def _create_session(self) -> None:
        """Spawn npx process and perform MCP initialize handshake."""
        if not self._api_key:
            raise ThreadlinqsSessionError(
                "THREADLINQS_API_KEY is not set"
            )

        server_params = StdioServerParameters(
            command="npx",
            args=["intelthreadlinqs-mcp"],
            env={
                **os.environ,
                "THREADLINQS_API_KEY": self._api_key,
            },
        )

        try:
            # Create the stdio transport context
            self._stdio_context = stdio_client(server_params)
            read_stream, write_stream = await self._stdio_context.__aenter__()

            # Create and initialize the session
            self._read_write_context = ClientSession(read_stream, write_stream)
            self._session = await self._read_write_context.__aenter__()

            # Perform initialize handshake — MUST happen before any call_tool
            await self._session.initialize()
            self._initialized = True

            logger.info("Threadlinqs MCP session established and initialized")

        except Exception as exc:
            await self._cleanup()
            raise ThreadlinqsSessionError(
                f"Failed to create Threadlinqs session: {exc}"
            ) from exc

    async def _cleanup(self) -> None:
        """Clean up session and transport resources."""
        self._initialized = False
        self._session = None

        if self._read_write_context is not None:
            try:
                await self._read_write_context.__aexit__(None, None, None)
            except Exception:
                pass
            self._read_write_context = None

        if self._stdio_context is not None:
            try:
                await self._stdio_context.__aexit__(None, None, None)
            except Exception:
                pass
            self._stdio_context = None

    async def connect(self) -> None:
        """Establish the MCP session if not already connected."""
        async with self._lock:
            if not self.is_connected:
                await self._create_session()

    async def reconnect(self) -> None:
        """Force a reconnect by tearing down and recreating the session."""
        async with self._lock:
            logger.warning("Reconnecting Threadlinqs MCP session")
            await self._cleanup()
            await self._create_session()

    async def disconnect(self) -> None:
        """Gracefully disconnect the MCP session."""
        async with self._lock:
            await self._cleanup()
            logger.info("Threadlinqs MCP session disconnected")

    @_breaker
    async def call_tool(
        self, tool_name: str, arguments: dict[str, Any] | None = None
    ) -> Any:
        """Call a tool on the Threadlinqs MCP server.

        Applies rate limiting and circuit breaking. Reconnects on session
        failures automatically.

        Args:
            tool_name: Name of the MCP tool to invoke.
            arguments: Arguments dict for the tool.

        Returns:
            The tool result from the MCP server.

        Raises:
            RateLimitExceeded: Daily limit exhausted.
            CircuitOpenError: Too many recent failures.
            ThreadlinqsClientError: Session or call failure.
        """
        await _rate_limiter.acquire()

        if not self.is_connected:
            await self.connect()

        try:
            assert self._session is not None
            result = await self._session.call_tool(
                tool_name, arguments=arguments or {}
            )
            return result
        except (ConnectionError, BrokenPipeError, EOFError, OSError) as exc:
            # Session lost — attempt reconnect for next call
            logger.warning(
                "Threadlinqs session lost during call_tool(%s): %s", tool_name, exc
            )
            try:
                await self.reconnect()
            except Exception:
                pass
            raise ThreadlinqsSessionError(
                f"Session lost during {tool_name}: {exc}"
            ) from exc

    async def list_tools(self) -> list[Any]:
        """List available tools on the Threadlinqs server."""
        if not self.is_connected:
            await self.connect()

        assert self._session is not None
        result = await self._session.list_tools()
        return list(result.tools) if hasattr(result, "tools") else []

    async def get_recent_threats(self, limit: int = 7) -> list[dict[str, Any]]:
        """Return the recent threat records from ``get_recent_threats``."""
        result = await self.call_tool("get_recent_threats", {"limit": limit})
        payload = _parse_tool_result(result)
        if isinstance(payload, dict):
            items = payload.get("items")
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        return []

    async def get_mitre_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Resolve MITRE metadata (name, tactic) for one technique id.

        Content-addressed cache and quota is the caller's concern; this only
        wraps the ``get_mitre_technique`` tool and parses the result. The live
        server names the technique under ``technique`` (aliased to ``name``).
        Returns None on any failure so a missing/unknown technique degrades
        gracefully.
        """
        result = await self.call_tool(
            "get_mitre_technique", {"technique_id": technique_id}
        )
        payload = _parse_tool_result(result)
        if isinstance(payload, dict):
            out: dict[str, Any] = {}
            if payload.get("name") is not None:
                out["name"] = payload["name"]
            elif payload.get("technique") is not None:
                out["name"] = payload["technique"]
            for key in ("tactic", "technique_id", "tactic_id"):
                if payload.get(key) is not None:
                    out[key] = payload[key]
            return out if out else None
        return None

    @property
    def rate_limiter(self) -> DailyRateLimiter:
        """Expose rate limiter for monitoring."""
        return _rate_limiter

    @staticmethod
    def _key_from_settings() -> str:
        """Try to read the key from pydantic Settings (canonical source)."""
        try:
            from app.core.config import settings
            return settings.threadlinqs_api_key
        except Exception:
            return ""

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        """Expose circuit breaker for monitoring."""
        return _breaker
