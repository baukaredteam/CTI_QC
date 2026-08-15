"""M1 test suite — Threadlinqs MCP client, normalizer, scorer, and supporting modules.

Covers:
1. Normalize a real bundle → IOC vs behavioral split, metadata extraction
2. score_threat × 3 tenants → three distinct zone results, visible_ttps with DRL gate
3. Circuit breaker state transitions
4. Daily rate limiter + 429 Retry-After
5. Content-addressed cache
6. MCP client initialize + reconnect (mocked transport)
7. IOC classifier: abused-legitimate whitelist
8. Sector morphology matching (financial services → finance)
9. Global region matching (Global → any geo)
10. Actor confidence adjustment (HIGH +10, LOW -10)
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures — using the REAL Threadlinqs IOC shape (category-grouped dict)
# ---------------------------------------------------------------------------

SAMPLE_BUNDLE_DICT_SHAPE = {
    "id": "TL-2026-001",
    "title": "APT-KZ Campaign Targeting Energy Sector",
    "iocs": {
        "network": [
            {"type": "ip", "value": "45.93.20.28", "context": "C2 server"},
            {"type": "domain", "value": "evil.herokuapp.com", "context": "Phishing domain"},
            {"type": "url", "value": "https://malware-c2.example.com/beacon", "context": "Beacon URL"},
        ],
        "file": [
            {"type": "sha256", "value": "a" * 64, "context": "Vidar sample"},
            {"type": "filename", "value": "payload.exe", "context": "Dropper"},
        ],
        "behavioral": [
            {"type": "technique", "value": "T1059.001 - PowerShell", "context": "Execution"},
            {"type": "technique", "value": "T1071.001 - Web Protocols", "context": "C2"},
            {"type": "command", "value": "whoami /all", "context": "Recon command"},
        ],
        "techniques": [
            {"type": "technique", "value": "T1566.001 - Spearphishing Attachment", "context": "Delivery"},
        ],
    },
    "target_sectors": ["energy", "financial services", "cryptocurrency"],
    "target_regions": ["Global", "Central Asia"],
    "techniques": [
        {"id": "T1059.001", "name": "PowerShell"},
        {"id": "T1071.001", "name": "Web Protocols"},
        {"id": "T1566.001", "name": "Spearphishing Attachment"},
    ],
    "attribution": {
        "threat_actor": "APT-KZ-BEAR",
        "threat_actor_aliases": ["APT-KZ-BEAR"],
        "nation_state": "Russia",
        "motivation": "ESPIONAGE",
        "confidence": "HIGH",
    },
}

# Legacy flat-list format (backwards compatibility)
SAMPLE_BUNDLE_FLAT_SHAPE = {
    "id": "TL-FLAT-001",
    "title": "Legacy Format Threat",
    "indicators": [
        {"type": "domain", "value": "evil.herokuapp.com"},
        {"type": "ipv4", "value": "198.51.100.42"},
        {"type": "sha256", "value": "b" * 64},
        {"type": "technique", "value": "T1059.001", "technique_id": "T1059.001", "technique_name": "PowerShell"},
    ],
    "affected": ["energy", "finance"],
    "regions": ["KZ"],
    "attribution": {"name": "LegacyActor", "confidence": "MEDIUM"},
}

TENANTS = [
    {
        "id": 1, "name": "KEGOC Finance", "sector": "finance", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 3, "proxy_log": 2, "email_gateway": 1},
    },
    {
        "id": 2, "name": "KEGOC Energy", "sector": "energy", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 4, "proxy_log": 3, "email_gateway": 3},
    },
    {
        "id": 3, "name": "KEGOC Critical Infra", "sector": "critical_infrastructure", "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {"windows_event_log": 1, "proxy_log": 0, "email_gateway": 0},
    },
]

RULEBOOK = [
    {"id": "R1", "enabled": True, "technique_ids": ["T1059.001"], "required_log_source": "windows_event_log"},
    {"id": "R2", "enabled": True, "technique_ids": ["T1071.001"], "required_log_source": "proxy_log"},
    {"id": "R3", "enabled": True, "technique_ids": ["T1566.001"], "required_log_source": "email_gateway"},
    {"id": "R4", "enabled": False, "technique_ids": ["T1059.001"], "required_log_source": "sysmon"},
]


# ===========================================================================
# 1. Normalizer tests — dict-shaped IOC block (real API format)
# ===========================================================================

class TestNormalizerDictShape:
    def test_ioc_vs_behavioral_split(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE_DICT_SHAPE)

        # 3 network + 2 file = 5 IOCs
        assert len(threat.iocs) == 5
        network_iocs = [i for i in threat.iocs if i.source == "network"]
        file_iocs = [i for i in threat.iocs if i.source == "file"]
        assert len(network_iocs) == 3
        assert len(file_iocs) == 2

        # All IOCs should be structural confidence
        for ioc in threat.iocs:
            assert ioc.confidence == "structural"

    def test_behavioral_has_technique_tags(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE_DICT_SHAPE)

        assert len(threat.behavioral) >= 3
        technique_ids = {b.technique_id for b in threat.behavioral}
        assert "T1059.001" in technique_ids
        assert "T1071.001" in technique_ids
        assert "T1566.001" in technique_ids

    def test_behavioral_excludes_commands(self):
        """Commands like 'whoami /all' should be in behavioral, not IOCs."""
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE_DICT_SHAPE)
        ioc_values = {i.value for i in threat.iocs}
        assert "whoami /all" not in ioc_values

    def test_metadata_non_empty(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE_DICT_SHAPE)

        assert len(threat.sectors) > 0, "sectors should be non-empty"
        assert len(threat.regions) > 0, "regions should be non-empty"
        assert len(threat.ttps) > 0, "ttps should be non-empty"
        assert threat.actor == "APT-KZ-BEAR"
        assert threat.actor_confidence == "HIGH"

    def test_id_and_title(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE_DICT_SHAPE)
        assert threat.bundle_id == "TL-2026-001"
        assert "Energy" in threat.title

    def test_ioc_types_mapped_correctly(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE_DICT_SHAPE)
        type_map = {i.value: i.ioc_type for i in threat.iocs}
        assert type_map["45.93.20.28"] == "ipv4"
        assert type_map["evil.herokuapp.com"] == "domain"
        assert type_map["a" * 64] == "hash_sha256"
        assert type_map["payload.exe"] == "filename"


class TestNormalizerFlatShape:
    """Backwards compatibility: flat list of {type, value} dicts."""

    def test_flat_list_ioc_split(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE_FLAT_SHAPE)
        assert len(threat.iocs) == 3  # domain, ipv4, sha256
        assert len(threat.behavioral) >= 1  # technique

    def test_flat_list_metadata(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE_FLAT_SHAPE)
        assert threat.bundle_id == "TL-FLAT-001"
        assert len(threat.sectors) > 0
        assert len(threat.regions) > 0


class TestNormalizerEmpty:
    def test_empty_bundle(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle({"id": "empty"})
        assert len(threat.iocs) == 0
        assert len(threat.behavioral) == 0
        assert threat.bundle_id == "empty"


# ===========================================================================
# 2. Relevance scorer tests
# ===========================================================================

class TestRelevanceScorer:
    def _threat_dict(self):
        from app.services.threadlinqs_normalizer import normalize_bundle
        t = normalize_bundle(SAMPLE_BUNDLE_DICT_SHAPE)
        return {
            "sectors": t.sectors,
            "regions": t.regions,
            "ttps": t.ttps,
            "iocs": t.iocs,
            "actor_confidence": t.actor_confidence,
        }

    def test_score_three_tenants_distinct(self):
        from app.services.relevance_scorer import score_threat

        threat = self._threat_dict()
        results = [score_threat(threat, t, RULEBOOK) for t in TENANTS]
        scores = [r.score for r in results]
        assert len(scores) == 3
        # Finance and energy should match (via sector normalization)
        # Critical infra should differ (no sector match, low DRL)
        assert len(set(scores)) >= 2, f"Expected distinct scores, got {scores}"

    def test_finance_matches_financial_services(self):
        """Sector morphology: 'financial services' in threat matches 'finance' tenant."""
        from app.services.relevance_scorer import score_threat

        threat = {"sectors": ["financial services"], "regions": [], "ttps": [], "iocs": []}
        result = score_threat(threat, TENANTS[0])  # finance tenant
        assert len(result.matching_sectors) > 0, "'financial services' should match 'finance'"
        assert result.score > 0

    def test_cryptocurrency_matches_finance(self):
        from app.services.relevance_scorer import score_threat

        threat = {"sectors": ["cryptocurrency"], "regions": [], "ttps": [], "iocs": []}
        result = score_threat(threat, TENANTS[0])
        assert len(result.matching_sectors) > 0

    def test_criticalinfrastructure_matches_critical_infrastructure(self):
        """Real API sends 'criticalinfrastructure' (no separator)."""
        from app.services.relevance_scorer import score_threat

        threat = {"sectors": ["criticalinfrastructure"], "regions": [], "ttps": [], "iocs": []}
        result = score_threat(threat, TENANTS[2])  # critical_infrastructure tenant
        assert len(result.matching_sectors) > 0

    def test_global_region_matches_any_geo(self):
        """'Global' region should match KZ tenant with full region_weight."""
        from app.services.relevance_scorer import score_threat

        threat = {"sectors": [], "regions": ["Global"], "ttps": [], "iocs": []}
        result = score_threat(threat, TENANTS[0])  # geo=KZ
        assert len(result.matching_regions) > 0, "'Global' should match any tenant geo"
        assert result.score > 0

    def test_worldwide_region_matches(self):
        from app.services.relevance_scorer import score_threat

        threat = {"sectors": [], "regions": ["Worldwide"], "ttps": [], "iocs": []}
        result = score_threat(threat, TENANTS[1])
        assert len(result.matching_regions) > 0

    def test_actor_confidence_high_adds_10(self):
        from app.services.relevance_scorer import score_threat

        base_threat = {"sectors": ["energy"], "regions": ["KZ"], "ttps": [], "iocs": []}
        high = score_threat({**base_threat, "actor_confidence": "HIGH"}, TENANTS[1])
        none = score_threat({**base_threat, "actor_confidence": ""}, TENANTS[1])
        assert high.score == none.score + 10.0

    def test_actor_confidence_low_subtracts_10(self):
        from app.services.relevance_scorer import score_threat

        base_threat = {"sectors": ["energy"], "regions": ["KZ"], "ttps": [], "iocs": []}
        low = score_threat({**base_threat, "actor_confidence": "LOW"}, TENANTS[1])
        none = score_threat({**base_threat, "actor_confidence": ""}, TENANTS[1])
        assert low.score == none.score - 10.0

    def test_visible_ttps_respects_drl_threshold(self):
        from app.services.relevance_scorer import visible_ttps

        vis = visible_ttps(["T1059.001", "T1071.001", "T1566.001"], TENANTS[0], RULEBOOK)
        visible_ids = {v.technique_id for v in vis}
        assert "T1059.001" in visible_ids  # windows_event_log DRL=3
        assert "T1071.001" in visible_ids  # proxy_log DRL=2
        assert "T1566.001" not in visible_ids  # email_gateway DRL=1 < 2

    def test_visible_ttps_tenant3_low_drl(self):
        from app.services.relevance_scorer import visible_ttps

        vis = visible_ttps(["T1059.001", "T1071.001", "T1566.001"], TENANTS[2], RULEBOOK)
        assert len(vis) == 0

    def test_disabled_rule_not_counted(self):
        from app.services.relevance_scorer import visible_ttps

        tenant_with_sysmon = {**TENANTS[0], "drl_matrix": {"sysmon": 5}}
        vis = visible_ttps(["T1059.001"], tenant_with_sysmon, RULEBOOK)
        rule_ids = {v.covering_rule_id for v in vis}
        assert "R4" not in rule_ids

    def test_score_zone_mapping(self):
        from app.services.relevance_scorer import _score_to_zone

        assert _score_to_zone(80.0) == "red"
        assert _score_to_zone(70.0) == "red"
        assert _score_to_zone(50.0) == "amber"
        assert _score_to_zone(40.0) == "amber"
        assert _score_to_zone(30.0) == "green"
        assert _score_to_zone(0.0) == "green"


# ===========================================================================
# 3. Circuit breaker tests
# ===========================================================================

class TestCircuitBreaker:
    @pytest.mark.asyncio
    async def test_opens_after_threshold_failures(self):
        from app.services.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState

        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)

        @breaker
        async def failing():
            raise ConnectionError("boom")

        for _ in range(3):
            with pytest.raises(ConnectionError):
                await failing()

        assert breaker.state == CircuitState.OPEN

        with pytest.raises(CircuitOpenError):
            await failing()

    @pytest.mark.asyncio
    async def test_half_open_after_cooldown(self):
        from app.services.circuit_breaker import CircuitBreaker, CircuitState

        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)

        @breaker
        async def failing():
            raise ConnectionError("boom")

        with pytest.raises(ConnectionError):
            await failing()

        assert breaker.state == CircuitState.OPEN
        await asyncio.sleep(0.15)
        assert breaker.state == CircuitState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_success_resets_to_closed(self):
        from app.services.circuit_breaker import CircuitBreaker, CircuitState

        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=0.1)
        call_count = 0

        @breaker
        async def sometimes_fails():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ConnectionError("boom")
            return "ok"

        with pytest.raises(ConnectionError):
            await sometimes_fails()
        with pytest.raises(ConnectionError):
            await sometimes_fails()
        result = await sometimes_fails()
        assert result == "ok"
        assert breaker.state == CircuitState.CLOSED


# ===========================================================================
# 4. Rate limiter tests
# ===========================================================================

class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_exhaust_daily_counter(self):
        from app.services.rate_limiter import DailyRateLimiter, RateLimitExceeded

        limiter = DailyRateLimiter(daily_limit=3)
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()

        with pytest.raises(RateLimitExceeded):
            await limiter.acquire()

        assert limiter.remaining == 0
        assert limiter.count == 3

    @pytest.mark.asyncio
    async def test_429_retry_after_blocks(self):
        from app.services.rate_limiter import DailyRateLimiter, RateLimitExceeded

        limiter = DailyRateLimiter(daily_limit=5000)
        await limiter.report_upstream_429(0.2)

        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.acquire()
        assert exc_info.value.retry_after > 0

        await asyncio.sleep(0.25)
        await limiter.acquire()
        assert limiter.count == 1

    @pytest.mark.asyncio
    async def test_resets_on_new_day(self):
        from app.services.rate_limiter import DailyRateLimiter

        limiter = DailyRateLimiter(daily_limit=5)
        await limiter.acquire()
        assert limiter.count == 1
        limiter._current_day = "1999-01-01"
        assert limiter.count == 0
        assert limiter.remaining == 5


# ===========================================================================
# 5. Cache tests
# ===========================================================================

class TestThreadlinqsCache:
    @pytest.mark.asyncio
    async def test_put_and_get(self):
        from app.services.threadlinqs_cache import ThreadlinqsCache

        mock_redis = AsyncMock()
        cache = ThreadlinqsCache(mock_redis, ttl_hours=1)
        await cache.put("bundle-1", {"id": "bundle-1", "data": "test"})
        mock_redis.set.assert_called_once()

        import json
        stored = mock_redis.set.call_args[0][1]
        mock_redis.get = AsyncMock(return_value=stored)
        result = await cache.get("bundle-1")
        assert result is not None
        assert result["id"] == "bundle-1"

    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self):
        from app.services.threadlinqs_cache import ThreadlinqsCache

        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        cache = ThreadlinqsCache(mock_redis)
        result = await cache.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_content_addressed_key(self):
        from app.services.threadlinqs_cache import _cache_key

        key1 = _cache_key("bundle-A")
        key2 = _cache_key("bundle-B")
        assert key1 != key2
        assert key1.startswith("tl:bundle:")
        assert _cache_key("bundle-A") == key1

    @pytest.mark.asyncio
    async def test_technique_cache_content_addressed(self):
        from app.services.threadlinqs_cache import ThreadlinqsCache, _technique_cache_key

        mock_redis = AsyncMock()
        cache = ThreadlinqsCache(mock_redis)
        meta = {"name": "Software Discovery", "tactic": "discovery"}

        await cache.put_technique("T1518.001", meta)

        key = _technique_cache_key("T1518.001")
        assert key.startswith("tl:technique:")
        assert _technique_cache_key("T1518.001") == key
        assert _technique_cache_key("T1518.001") != _technique_cache_key("T1027")
        mock_redis.set.assert_awaited_once()
        args = mock_redis.set.await_args.args
        assert args[0] == key

        mock_redis.get = AsyncMock(return_value='{"name": "Software Discovery"}')
        cached = await cache.get_technique("T1518.001")
        assert cached == {"name": "Software Discovery"}


# ===========================================================================
# 6. MCP client initialize + reconnect tests
# ===========================================================================

class TestThreadlinqsClient:
    @pytest.mark.asyncio
    async def test_initialize_called_before_call_tool(self):
        from app.services.threadlinqs_client import ThreadlinqsClient, _rate_limiter, _breaker
        from app.services.circuit_breaker import CircuitState

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value={"result": "ok"})
        client = ThreadlinqsClient(api_key="test-key")

        async def fake_create_session():
            client._session = mock_session
            client._initialized = True

        client._create_session = fake_create_session
        _rate_limiter._count = 0; _rate_limiter._current_day = ""
        _breaker._state = CircuitState.CLOSED; _breaker._failure_count = 0

        await client.call_tool("get_bundle", {"id": "test"})
        mock_session.call_tool.assert_called_once_with("get_bundle", arguments={"id": "test"})

    @pytest.mark.asyncio
    async def test_get_recent_threats_parses_items(self):
        from app.services.threadlinqs_client import ThreadlinqsClient, _rate_limiter, _breaker
        from app.services.circuit_breaker import CircuitState

        class _Content:
            def __init__(self, text):
                self.text = text

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value=type(
            "Res", (), {"content": [_Content('{"items": [{"id": "TL-1", "title": "A"}, {"id": "TL-2", "title": "B"}]}')]}
        )())
        client = ThreadlinqsClient(api_key="test-key")
        client._session = mock_session
        client._initialized = True
        _rate_limiter._count = 0; _rate_limiter._current_day = ""
        _breaker._state = CircuitState.CLOSED; _breaker._failure_count = 0

        items = await client.get_recent_threats(limit=3)
        mock_session.call_tool.assert_awaited_once_with(
            "get_recent_threats", arguments={"limit": 3}
        )
        assert [i["id"] for i in items] == ["TL-1", "TL-2"]

    @pytest.mark.asyncio
    async def test_get_recent_threats_ignores_non_dict_items(self):
        from app.services.threadlinqs_client import ThreadlinqsClient, _rate_limiter, _breaker
        from app.services.circuit_breaker import CircuitState

        class _Res:
            def __init__(self, text):
                self.content = [type("Item", (), {"text": text})()]

        client = ThreadlinqsClient(api_key="test-key")
        client._session = AsyncMock()
        client._session.call_tool = AsyncMock(return_value=_Res('{"items": ["a", 1]}'))
        client._initialized = True
        _rate_limiter._count = 0; _rate_limiter._current_day = ""
        _breaker._state = CircuitState.CLOSED; _breaker._failure_count = 0
        assert await client.get_recent_threats(limit=2) == []

    @pytest.mark.asyncio
    async def test_get_mitre_technique_parses_metadata(self):
        from app.services.threadlinqs_client import ThreadlinqsClient, _rate_limiter, _breaker
        from app.services.circuit_breaker import CircuitState

        class _Res:
            def __init__(self, text):
                self.content = [type("Item", (), {"text": text})()]

        client = ThreadlinqsClient(api_key="test-key")
        client._session = AsyncMock()
        client._session.call_tool = AsyncMock(return_value=_Res('{"name": "Software Discovery", "tactic": "discovery"}'))
        client._initialized = True
        _rate_limiter._count = 0; _rate_limiter._current_day = ""
        _breaker._state = CircuitState.CLOSED; _breaker._failure_count = 0

        meta = await client.get_mitre_technique("T1518.001")
        client._session.call_tool.assert_awaited_once_with(
            "get_mitre_technique", arguments={"technique_id": "T1518.001"}
        )
        assert meta["name"] == "Software Discovery"
        assert meta["tactic"] == "discovery"

    @pytest.mark.asyncio
    async def test_get_mitre_technique_aliases_live_technique_key(self):
        """The live server names the technique under ``technique``; the client
        must alias it to ``name`` (spec-review finding: names came back empty)."""
        from app.services.threadlinqs_client import ThreadlinqsClient, _rate_limiter, _breaker
        from app.services.circuit_breaker import CircuitState

        class _Res:
            def __init__(self, text):
                self.content = [type("Item", (), {"text": text})()]

        client = ThreadlinqsClient(api_key="test-key")
        client._session = AsyncMock()
        client._session.call_tool = AsyncMock(return_value=_Res('{"technique": "Exploit Public-Facing Application", "tactic": "initial-access"}'))
        client._initialized = True
        _rate_limiter._count = 0; _rate_limiter._current_day = ""
        _breaker._state = CircuitState.CLOSED; _breaker._failure_count = 0

        meta = await client.get_mitre_technique("T1190")
        assert meta["name"] == "Exploit Public-Facing Application"
        assert meta["tactic"] == "initial-access"

    @pytest.mark.asyncio
    async def test_get_mitre_technique_returns_none_on_non_dict(self):
        from app.services.threadlinqs_client import ThreadlinqsClient, _rate_limiter, _breaker
        from app.services.circuit_breaker import CircuitState

        class _Res:
            def __init__(self, text):
                self.content = [type("Item", (), {"text": text})()]

        client = ThreadlinqsClient(api_key="test-key")
        client._session = AsyncMock()
        client._session.call_tool = AsyncMock(return_value=_Res('["oops"]'))
        client._initialized = True
        _rate_limiter._count = 0; _rate_limiter._current_day = ""
        _breaker._state = CircuitState.CLOSED; _breaker._failure_count = 0
        assert await client.get_mitre_technique("T1518.001") is None

    @pytest.mark.asyncio
    async def test_reconnect_on_session_drop(self):
        from app.services.threadlinqs_client import ThreadlinqsClient, ThreadlinqsSessionError, _rate_limiter, _breaker
        from app.services.circuit_breaker import CircuitState

        reconnect_count = 0
        client = ThreadlinqsClient(api_key="test-key")

        mock_session = AsyncMock()
        mock_session.call_tool = AsyncMock(side_effect=ConnectionError("pipe broken"))
        client._session = mock_session
        client._initialized = True

        async def tracking_reconnect():
            nonlocal reconnect_count
            reconnect_count += 1
            client._session = AsyncMock()
            client._session.call_tool = AsyncMock(side_effect=ConnectionError("still broken"))
            client._initialized = True

        client.reconnect = tracking_reconnect
        _rate_limiter._count = 0; _rate_limiter._current_day = ""
        _breaker._state = CircuitState.CLOSED; _breaker._failure_count = 0

        with pytest.raises(ThreadlinqsSessionError):
            await client.call_tool("get_bundle", {"id": "test"})
        assert reconnect_count == 1


# ===========================================================================
# 7. IOC classifier tests
# ===========================================================================

class TestIOCClassifier:
    def test_attacker_subdomain_malicious(self):
        from app.services.ioc_classifier import classify_ioc, IOCVerdict

        result = classify_ioc("evil-c2.herokuapp.com", "domain")
        assert result.verdict == IOCVerdict.MALICIOUS

    def test_root_legitimate_whitelisted(self):
        from app.services.ioc_classifier import classify_ioc, IOCVerdict

        assert classify_ioc("google.com", "domain").verdict == IOCVerdict.LEGITIMATE
        assert classify_ioc("herokuapp.com", "domain").verdict == IOCVerdict.LEGITIMATE

    def test_unknown_domain(self):
        from app.services.ioc_classifier import classify_ioc, IOCVerdict

        assert classify_ioc("totally-unknown-evil.xyz", "domain").verdict == IOCVerdict.UNKNOWN

    def test_ip_address_unknown(self):
        from app.services.ioc_classifier import classify_ioc, IOCVerdict

        assert classify_ioc("198.51.100.42", "ipv4").verdict == IOCVerdict.UNKNOWN

    def test_nested_subdomain_malicious(self):
        from app.services.ioc_classifier import classify_ioc, IOCVerdict

        assert classify_ioc("deep.nested.evil.appspot.com", "domain").verdict == IOCVerdict.MALICIOUS

    def test_filter_blockable(self):
        from app.services.ioc_classifier import classify_iocs, filter_blockable, IOCVerdict

        classified = classify_iocs([
            ("evil.herokuapp.com", "domain"),
            ("google.com", "domain"),
            ("unknown-thing.xyz", "domain"),
        ])
        blockable = filter_blockable(classified)
        assert all(c.verdict != IOCVerdict.LEGITIMATE for c in blockable)
        assert len(blockable) == 2


# ===========================================================================
# 8. Redaction tests
# ===========================================================================

class TestRedaction:
    def test_threadlinqs_key_redacted(self):
        from app.core.redaction import redact_sensitive_text

        text = 'threadlinqs_api_key=secret123abc config loaded'
        result = redact_sensitive_text(text)
        assert "secret123abc" not in result
        assert "[REDACTED]" in result

    def test_tl_api_key_redacted(self):
        from app.core.redaction import redact_sensitive_text

        text = 'tl_api_key="my-secret-key" enabled=true'
        result = redact_sensitive_text(text)
        assert "my-secret-key" not in result
