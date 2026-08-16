"""Ticket 06 — ThreadlinqsClient additively added MCP methods (verified protocol).

Protocol verified against the authoritative intelthreadlinqs-mcp@7.1.0 tool
registry (dist/index.js installed globally via npm):

- ``get_threat_hunting_bundle``   inputSchema ``{threat_id}`` only
- ``predict_mitre_transitions``   ``{technique_id, direction, top_n, basis}``
- ``get_attack_flow``             ``{threat_id}`` only
- ``export_stix``                 ABSENT in 7.1.0 — the server itself says
                                  "STIX export could be a roadmap ask", so no
                                  contract was invented (NEEDS_DECISION).

Every method degrades gracefully (empty dict, no exception) on disabled
config (``settings.threadlinqs_enabled`` false), open breaker, rate limit,
timeout, session failure, or malformed/non-dict payload.
"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.core.config import settings
from app.services.circuit_breaker import CircuitOpenError, CircuitState
from app.services.rate_limiter import RateLimitExceeded
from app.services.threadlinqs_client import (
    ThreadlinqsClient,
    ThreadlinqsClientError,
    ThreadlinqsSessionError,
    _breaker,
    _rate_limiter,
)


# ---------------------------------------------------------------------------
# Shared helpers — same seam as test_m1_threadlinqs
# ---------------------------------------------------------------------------


class _Res:
    """MCP call_tool result stub: ``.content = [SimpleNamespace(text=...)]``."""

    def __init__(self, text: str) -> None:
        self.content = [SimpleNamespace(text=text)]


def _reset_globals() -> None:
    """Reset module-level breaker / rate-limiter between tests."""
    _rate_limiter._count = 0
    _rate_limiter._current_day = ""
    _breaker._state = CircuitState.CLOSED
    _breaker._failure_count = 0
    _breaker._last_failure_time = 0.0


def _client(api_key: str = "test-key", *, enabled: bool = True) -> ThreadlinqsClient:
    """Build a client with a mocked session (no npx spawn)."""
    client = ThreadlinqsClient(api_key=api_key)
    client._session = AsyncMock()
    client._initialized = True
    _reset_globals()
    # Patch settings.threadlinqs_enabled for all success / fallback tests
    settings.threadlinqs_enabled = enabled  # noqa: B015 — mutable singleton
    return client


# ---------------------------------------------------------------------------
# 1. Success shapes + exact argument mapping (3 verified tools)
# ---------------------------------------------------------------------------

THREAT_HUNTING_ENVELOPE = {
    "threat": {"id": "TL-2026-1693", "title": "Test Threat"},
    "iocs": {"network": [], "file": [], "behavioral": [], "techniques": []},
    "detections": [],
    "similar_threats": [],
    "simulations": [],
    "infrastructure_pivots": [],
    "meta": {"threat_id": "TL-2026-1693", "tools": [], "resource_calls": []},
    "techniques": [{"id": "T1059", "name": "PowerShell"}],
}

PREDICT_TRANSITIONS_ENVELOPE = {
    "predicted_next_techniques": ["T1059.001", "T1548"],
    "predicted_prev_techniques": ["T1566.001"],
}

ATTACK_FLOW_ENVELOPE = {
    "attack_flow": {"id": "AF-1"},
    "nodes": [{"id": "T1059", "label": "PowerShell"}],
    "edges": [{"source": "T1566", "target": "T1059"}],
}


@pytest.mark.asyncio
async def test_threat_hunting_bundle_passes_only_threat_id():
    """v7.1.0 schema has no simulation_limit / pivot_limit — only threat_id."""
    client = _client()
    client._session.call_tool = AsyncMock(return_value=_Res(json.dumps(THREAT_HUNTING_ENVELOPE)))

    result = await client.get_threat_hunting_bundle("TL-2026-1693", simulation_limit=5, pivot_limit=10)

    assert result == THREAT_HUNTING_ENVELOPE
    client._session.call_tool.assert_awaited_once_with(
        "get_threat_hunting_bundle",
        arguments={"threat_id": "TL-2026-1693"},
    )


@pytest.mark.asyncio
async def test_predict_mitre_transitions_default_args():
    """All four parameters are forwarded (defaults included for determinism)."""
    client = _client()
    client._session.call_tool = AsyncMock(return_value=_Res(json.dumps(PREDICT_TRANSITIONS_ENVELOPE)))

    result = await client.predict_mitre_transitions("T1059")

    assert result == PREDICT_TRANSITIONS_ENVELOPE
    client._session.call_tool.assert_awaited_once_with(
        "predict_mitre_transitions",
        arguments={
            "technique_id": "T1059",
            "direction": "forward",
            "top_n": 5,
            "basis": "any",
        },
    )


@pytest.mark.asyncio
async def test_predict_mitre_transitions_nondefault_args():
    """Non-default arguments are passed through verbatim."""
    client = _client()
    client._session.call_tool = AsyncMock(return_value=_Res(json.dumps(PREDICT_TRANSITIONS_ENVELOPE)))

    result = await client.predict_mitre_transitions("T1059", direction="backward", top_n=10, basis="simulations")

    assert result == PREDICT_TRANSITIONS_ENVELOPE
    client._session.call_tool.assert_awaited_once_with(
        "predict_mitre_transitions",
        arguments={
            "technique_id": "T1059",
            "direction": "backward",
            "top_n": 10,
            "basis": "simulations",
        },
    )


@pytest.mark.asyncio
async def test_get_attack_flow_passes_threat_id_and_returns_envelope():
    client = _client()
    client._session.call_tool = AsyncMock(return_value=_Res(json.dumps(ATTACK_FLOW_ENVELOPE)))

    result = await client.get_attack_flow("TL-2026-1693")

    assert result == ATTACK_FLOW_ENVELOPE
    client._session.call_tool.assert_awaited_once_with(
        "get_attack_flow",
        arguments={"threat_id": "TL-2026-1693"},
    )


@pytest.mark.asyncio
async def test_export_stix_not_invented():
    """Pin the NEEDS_DECISION: export_stix is absent in v7.1.0."""
    client = _client()
    assert not hasattr(client, "export_stix")


# ---------------------------------------------------------------------------
# 2. Degradation matrix — disabled / breaker / timeout / session / malformed
# ---------------------------------------------------------------------------

_METHODS_AND_ARGS = [
    ("get_threat_hunting_bundle", ("TL-1",)),
    ("predict_mitre_transitions", ("T1059",)),
    ("get_attack_flow", ("TL-1",)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "args"), _METHODS_AND_ARGS)
async def test_disabled_config_returns_empty(method, args):
    """settings.threadlinqs_enabled=false → empty dict, no transport call."""
    client = _client(enabled=False)
    session = client._session

    result = await getattr(client, method)(*args)

    assert result == {}
    session.call_tool.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "args"), _METHODS_AND_ARGS)
async def test_breaker_open_returns_empty(method, args):
    """OPEN circuit → CircuitOpenError caught → empty dict."""
    client = _client()
    # Keep OPEN: set last_failure_time to now so recovery_timeout hasn't elapsed
    _breaker._state = CircuitState.OPEN
    _breaker._last_failure_time = time.monotonic()

    result = await getattr(client, method)(*args)

    assert result == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "args"), _METHODS_AND_ARGS)
async def test_timeout_returns_empty(method, args):
    """asyncio.TimeoutError propagated through call_tool → caught → empty."""
    client = _client()
    client._session.call_tool = AsyncMock(side_effect=asyncio.TimeoutError("timed out"))

    result = await getattr(client, method)(*args)

    assert result == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "args"), _METHODS_AND_ARGS)
async def test_session_failure_returns_empty(method, args):
    """ConnectionError → reconnect attempt → ThreadlinqsSessionError → empty."""
    client = _client()
    client._session.call_tool = AsyncMock(side_effect=ConnectionError("pipe broken"))
    client.reconnect = AsyncMock()  # avoid real npx spawn

    result = await getattr(client, method)(*args)

    assert result == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "args"), _METHODS_AND_ARGS)
async def test_malformed_payload_returns_empty(method, args):
    """Non-JSON / JSON non-object → _parse_tool_result returns str/list → empty."""
    client = _client()
    client._session.call_tool = AsyncMock(return_value=_Res("not-json"))

    result = await getattr(client, method)(*args)

    assert result == {}


@pytest.mark.asyncio
async def test_malformed_json_array_returns_empty():
    """JSON array (not envelope dict) → empty."""
    client = _client()
    client._session.call_tool = AsyncMock(return_value=_Res('["oops"]'))

    result = await client.get_threat_hunting_bundle("TL-1")

    assert result == {}


# ---------------------------------------------------------------------------
# 3. Invariants — old methods unchanged, no new flags
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_existing_get_recent_threats_unchanged():
    client = _client()
    client._session.call_tool = AsyncMock(return_value=_Res('{"items": [{"id": "TL-1"}, {"id": "TL-2"}]}'))

    items = await client.get_recent_threats(limit=5)

    assert items == [{"id": "TL-1"}, {"id": "TL-2"}]
    client._session.call_tool.assert_awaited_once_with("get_recent_threats", arguments={"limit": 5})


@pytest.mark.asyncio
async def test_existing_get_mitre_technique_unchanged():
    client = _client()
    client._session.call_tool = AsyncMock(return_value=_Res('{"name": "PowerShell", "tactic": "execution", "technique_id": "T1059"}'))

    meta = await client.get_mitre_technique("T1059")

    assert meta == {"name": "PowerShell", "tactic": "execution", "technique_id": "T1059"}


# ---------------------------------------------------------------------------
# 4. No secret leak — api key never surfaces in return value
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "args"), _METHODS_AND_ARGS)
async def test_no_api_key_leak_on_timeout(method, args):
    """API key must not appear in return value on error path."""
    client = _client(api_key="sk-SUPERSECRET-xyz")
    client._session.call_tool = AsyncMock(side_effect=asyncio.TimeoutError("boom"))

    result = await getattr(client, method)(*args)

    assert result == {}
    assert "SUPERSECRET" not in str(result)
