"""M6.4 — integration test for the feed scanner (STEP 3/7).

Drives ``scan_feed`` end to end against a mocked recent-threat fetcher and a
mocked bundle loader, then asserts the generated hypotheses were persisted to
the store and are retrievable via the API seam. No network, no DB, no LLM:
the mocks stand in for ``ThreadlinqsClient``.

Mirrors the sibling offline seams (``test_hypothesis_generator.py``), asserting
the targeted spec top-level contract: relevance >= threshold -> coverage ->
hypotheses persisted, sorted by priority.
"""

from __future__ import annotations

import asyncio
import pathlib
from typing import Any

import pytest

from app.services.hypothesis_generator import generate_hypotheses
from app.services.hypothesis_store import (
    add_hypothesis,
    clear,
    get_hypothesis,
    list_hypotheses,
)
from app.services.rate_limiter import RateLimitExceeded
from app.services.rules_parser import parse_rules_file
from app.services.tenants_provider import require_tenant
from app.services.threadlinqs_cache import ThreadlinqsCache as _RealThreadlinqsCache
from app.services.threadlinqs_client import ThreadlinqsClientError
from app.tasks.feed_scanner import scan_feed

_RULES_YAML = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "full_rules85.yaml"

_THREAT_BUNDLE = {
    "id": "TL-2026-1693",
    "title": "Sauri",
    "sectors": ["finance", "cryptocurrency"],
    "regions": ["Global"],
    "ttps": ["T1027", "T1003.002", "T1078", "T1204", "T1102", "T1041", "T1486"],
    "iocs": [],
    "actor_confidence": "high",
}


@pytest.fixture(autouse=True)
def _isolated_file_store(monkeypatch, tmp_path):
    """Point the store at a temp file so the scanner never touches repo data."""
    clear()
    monkeypatch.setattr(
        "app.services.hypothesis_store._DEFAULT_FILE",
        tmp_path / "hypotheses.json",
    )
    yield
    clear()


async def _mock_use_feed_recent(_limit: int) -> list[dict]:
    return [{"threat_id": "TL-2026-1693"}]


async def _mock_bundle_loader(threat_id: str) -> dict:
    assert threat_id == "TL-2026-1693"
    return dict(_THREAT_BUNDLE)


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_scan_feed_persists_hypotheses_for_tenants(tmp_path):
    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
    )

    assert report["threats_scanned"] == 1
    assert report["skipped"] == 0
    assert report["generated"] >= 1

    rows = list_hypotheses(tenant_id="finance")
    assert rows
    for row in rows:
        assert row.threat_id == "TL-2026-1693"
        assert row.tenant_id == "finance"
        assert row.status == "proposed"

    saved = tmp_path / "hypotheses.json"
    assert saved.exists()


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_scan_feed_passes_limit_and_scans_multiple_threats(tmp_path):
    """Fix 1: ``fetch_recent`` receives the limit as a positional arg and the
    scan iterates every returned threat (not just the canonical default)."""

    captured_limits: list[int] = []

    async def _mock_fetch_three(_limit: int) -> list[dict]:
        captured_limits.append(_limit)
        return [
            {"threat_id": "TL-2026-1693"},
            {"threat_id": "TL-2026-1700"},
            {"threat_id": "TL-2026-1707"},
        ]

    seen: list[str] = []

    async def _mock_bundle_loader(threat_id: str) -> dict:
        seen.append(threat_id)
        if threat_id == "TL-2026-1700":
            return {"id": threat_id, "title": "Vidar", "sectors": ["finance"], "ttps": ["T1027"], "iocs": [], "actor_confidence": "low"}
        if threat_id == "TL-2026-1707":
            return {"id": threat_id, "title": "Lumma", "sectors": ["finance"], "ttps": ["T1204"], "iocs": [], "actor_confidence": "medium"}
        return dict(_THREAT_BUNDLE)

    report = await scan_feed(
        fetch_recent=_mock_fetch_three,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        limit=3,
        enrich=False,
    )

    assert captured_limits == [3]
    assert report["threats_scanned"] == 3
    assert report["skipped"] == 0
    assert report["generated"] >= 1

    all_tenants_rows = list_hypotheses(tenant_id="finance")
    fetched = {row.threat_id for row in all_tenants_rows}
    assert fetched <= {"TL-2026-1693", "TL-2026-1700", "TL-2026-1707"}


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_scan_feed_respects_relevance_threshold(tmp_path, caplog):
    """STEP 4: a threat under the relevance gate yields no hypotheses and logs progress."""
    import logging

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        min_relevance=99.0,
    )
    assert report["threats_scanned"] == 1
    assert report["generated"] == 0
    assert list_hypotheses(tenant_id="finance") == []

    with caplog.at_level(logging.INFO, logger="app.tasks.feed_scanner"):
        caplog.clear()
        await scan_feed(
            fetch_recent=_mock_use_feed_recent,
            bundle_loader=_mock_bundle_loader,
            rules_path=_RULES_YAML,
            tenants=[require_tenant("finance")],
            store_path=tmp_path / "hypotheses.json",
            min_relevance=0.0,
        )
    assert any(
        "generated" in record.message and "tenant finance" in record.message
        for record in caplog.records
    )


class _FakeLiveClient:
    """Stand-in for ThreadlinqsClient during a live scan; no network."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.bundle_calls: list[tuple[str, int, int]] = []
        self.predict_calls: list[tuple[str, str, int, str]] = []
        self.predict_error: BaseException | None = None
        self._inflight = 0
        self.max_inflight = 0

    async def get_mitre_technique(self, technique_id: str) -> dict | None:
        return None

    async def get_threat_hunting_bundle(
        self, threat_id: str, simulation_limit: int = 3, pivot_limit: int = 25
    ) -> dict:
        self.bundle_calls.append((threat_id, simulation_limit, pivot_limit))
        return {
            "id": threat_id,
            "title": "Sauri",
            "similar_threats": [{"name": "Kasablanka"}, {"name": "Sandworm"}],
            "simulations": [{"playbook": "Port Scan"}, {"playbook": "C2 Beacon"}],
            "infrastructure_pivots": [{"ipv4": "203.0.113.7", "asn": "AS1234"}],
        }

    async def predict_mitre_transitions(
        self,
        technique_id: str,
        direction: str = "forward",
        top_n: int = 5,
        basis: str = "any",
    ) -> dict:
        """Ticket 09B: record the call contract, then return a mixed-basis
        envelope; ``predict_error`` makes the fetch fail like a live outage."""
        self.predict_calls.append((technique_id, direction, top_n, basis))
        if self.predict_error is not None:
            raise self.predict_error
        self._inflight += 1
        self.max_inflight = max(self.max_inflight, self._inflight)
        try:
            await asyncio.sleep(0.01)
            return _prediction_envelope(technique_id)
        finally:
            self._inflight -= 1


def _prediction_envelope(technique_id: str) -> dict:
    """A predict_mitre_transitions envelope with one entry per basis."""
    return {
        "predicted_next_techniques": [
            {"technique_id": technique_id, "name": f"Next after {technique_id}", "probability": 0.85, "basis": "attack_flow"},
            {"technique_id": technique_id, "name": f"Canonical {technique_id}", "probability": 0.50, "basis": "mitre_canonical"},
            {"technique_id": technique_id, "name": f"Blended {technique_id}", "probability": 0.30, "basis": "blended"},
        ]
    }


class _FakeTechniqueCache:
    """In-memory stand-in for ThreadlinqsCache technique keys."""

    def __init__(self, seed: dict[str, dict] | None = None):
        self._store = dict(seed or {})
        self.puts: list[tuple[str, dict]] = []

    async def get_technique(self, technique_id: str) -> dict | None:
        return self._store.get(technique_id)

    async def put_technique(self, technique_id: str, meta: dict) -> None:
        self._store[technique_id] = dict(meta)
        self.puts.append((technique_id, meta))


class _FakeRedis:
    """Records Redis ``set`` kwargs so the real cache's TTL is observable."""

    def __init__(self):
        self.sets: list[tuple[str, str, dict]] = []

    async def get(self, key: str) -> None:
        return None

    async def set(self, key: str, value: str, **kwargs) -> bool:
        self.sets.append((key, value, kwargs))
        return True

    async def delete(self, key: str) -> bool:
        return True

    async def exists(self, key: str) -> bool:
        return False


class _BundleOnlyClient:
    """Client that can enrich bundles but has no predict seam (pass-through)."""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.bundle_calls: list[tuple[str, int, int]] = []

    async def get_mitre_technique(self, technique_id: str) -> dict | None:
        return None

    async def get_threat_hunting_bundle(
        self, threat_id: str, simulation_limit: int = 3, pivot_limit: int = 25
    ) -> dict:
        self.bundle_calls.append((threat_id, simulation_limit, pivot_limit))
        return {
            "id": threat_id,
            "similar_threats": [{"name": "Kasablanka"}],
            "simulations": [{"playbook": "Port Scan"}],
            "infrastructure_pivots": [{"ipv4": "203.0.113.7", "asn": "AS1234"}],
        }


def _patch_live(
    monkeypatch: pytest.MonkeyPatch, fake_client: Any, cache: Any = None
) -> None:
    """Wire scan_feed's live branch to a fake client + optional fake cache."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "threadlinqs_enabled", True)
    monkeypatch.setattr(settings, "redis_url", "redis://cache-test:6379/0" if cache is not None else "")
    monkeypatch.setattr(
        "app.services.threadlinqs_client.ThreadlinqsClient",
        lambda api_key="": fake_client,
    )
    if cache is not None:
        monkeypatch.setattr(
            "app.services.threadlinqs_cache.ThreadlinqsCache",
            lambda _redis: cache,
        )


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_scan_feed_live_path_enriches_hypotheses(tmp_path, monkeypatch):
    """Ticket 08: a live scan decorates hypotheses with MCP bundle facts before
    persistence — one ``get_threat_hunting_bundle`` call per threat with the
    ticket's fixed limits."""
    from app.core.config import settings

    fake = _FakeLiveClient("test-key")
    monkeypatch.setattr(settings, "threadlinqs_enabled", True)
    monkeypatch.setattr(settings, "redis_url", "")
    monkeypatch.setattr(
        "app.services.threadlinqs_client.ThreadlinqsClient",
        lambda api_key="": fake,
    )

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )

    assert report["generated"] >= 1
    assert fake.bundle_calls == [("TL-2026-1693", 3, 25)]

    rows = list_hypotheses(tenant_id="finance")
    assert rows
    for row in rows:
        assert row.related_threats == ["Kasablanka", "Sandworm"]
        assert row.adversary_playbooks == ["Port Scan", "C2 Beacon"]
        assert row.infrastructure_pivots == [{"ipv4": "203.0.113.7", "asn": "AS1234"}]
        assert "adversary playbooks: Port Scan, C2 Beacon." in row.expected_evidence_ru


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_live_scan_populates_predicted_next_techniques(tmp_path, monkeypatch):
    """A live scan persists attack_flow predictions — one batched
    ``predict_mitre_transitions("forward", 5, "any")`` call per unique
    technique, then only attack_flow entries surface in the stored field."""
    fake = _FakeLiveClient("test-key")
    _patch_live(monkeypatch, fake, cache=None)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )

    assert report["generated"] == 5
    predicted = {tid for tid, direction, top_n, basis in fake.predict_calls}
    assert predicted == {"T1003.002", "T1027", "T1041", "T1102", "T1486"}
    assert all(
        (direction, top_n, basis) == ("forward", 5, "any")
        for _, direction, top_n, basis in fake.predict_calls
    )

    rows = list_hypotheses(tenant_id="finance")
    assert rows
    for row in rows:
        assert row.predicted_next_techniques
        for item in row.predicted_next_techniques:
            assert item["basis"] == "attack_flow"
            assert item["technique_id"]
            assert item["name"]
            assert "probability" in item


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_offline_scan_predictions_empty(tmp_path):
    """Offline scans (enrich=False) stay pure: no predict calls, empty field."""
    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=False,
    )
    assert report["generated"] == 5
    for row in list_hypotheses(tenant_id="finance"):
        assert row.predicted_next_techniques == []


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_integration_disabled_predictions_empty(tmp_path, monkeypatch):
    """threadlinqs_enabled=False with enrich=True degrades to empty
    predictions without instantiating a client."""
    from app.core.config import settings

    fake = _FakeLiveClient("test-key")
    monkeypatch.setattr(settings, "threadlinqs_enabled", False)
    monkeypatch.setattr(settings, "redis_url", "")
    monkeypatch.setattr(
        "app.services.threadlinqs_client.ThreadlinqsClient",
        lambda api_key="": fake,
    )

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 5
    assert fake.predict_calls == []
    for row in list_hypotheses(tenant_id="finance"):
        assert row.predicted_next_techniques == []


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_cache_hit_skips_mcp_call(tmp_path, monkeypatch):
    """A warm tl:technique cache short-circuits predict fetches entirely."""
    techniques = {"T1003.002", "T1027", "T1041", "T1102", "T1486"}
    cache = _FakeTechniqueCache(
        seed={tid: _prediction_envelope(tid) for tid in techniques}
    )
    fake = _FakeLiveClient("test-key")
    _patch_live(monkeypatch, fake, cache=cache)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 5
    assert fake.predict_calls == []
    for row in list_hypotheses(tenant_id="finance"):
        assert row.predicted_next_techniques


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_cache_miss_one_call_per_technique_and_put(tmp_path, monkeypatch):
    """A cold cache triggers exactly one predict call per unique technique and
    stores the raw envelope via put_technique."""
    cache = _FakeTechniqueCache()
    fake = _FakeLiveClient("test-key")
    _patch_live(monkeypatch, fake, cache=cache)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 5
    assert len(fake.predict_calls) == 5
    assert sorted(tid for tid, _, _, _ in fake.predict_calls) == [
        "T1003.002",
        "T1027",
        "T1041",
        "T1102",
        "T1486",
    ]
    assert sorted(tid for tid, _ in cache.puts) == [
        "T1003.002",
        "T1027",
        "T1041",
        "T1102",
        "T1486",
    ]


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_technique_cache_ttl_seven_days(tmp_path, monkeypatch):
    """the tl:technique entries are written with a 7-day (604800s) TTL."""
    redis = _FakeRedis()
    cache = _RealThreadlinqsCache(redis)
    fake = _FakeLiveClient("test-key")
    _patch_live(monkeypatch, fake, cache=cache)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 5
    technique_sets = [
        (key, kwargs) for key, _value, kwargs in redis.sets if key.startswith("tl:technique:")
    ]
    assert len(technique_sets) == 5
    assert all(kwargs.get("ex") == 7 * 24 * 3600 for _, kwargs in technique_sets)


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_duplicate_technique_ids_share_one_call(tmp_path, monkeypatch):
    """Two tenants over the same technique set share one cache: the second
    tenant's predictions come from cache, never a second MCP call."""
    cache = _FakeTechniqueCache()
    fake = _FakeLiveClient("test-key")
    _patch_live(monkeypatch, fake, cache=cache)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance"), require_tenant("energy")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 10
    # 5 unique techniques fetch once; the energy tenant reuses the finance cache.
    assert len(fake.predict_calls) == 5
    assert sorted(tid for tid, _, _, _ in fake.predict_calls) == [
        "T1003.002",
        "T1027",
        "T1041",
        "T1102",
        "T1486",
    ]
    for tenant in ("finance", "energy"):
        for row in list_hypotheses(tenant_id=tenant):
            assert row.predicted_next_techniques


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_predictions_fetched_in_parallel_batches(tmp_path, monkeypatch):
    """Prediction fetches run concurrently (asyncio.gather) within one batch."""
    fake = _FakeLiveClient("test-key")
    _patch_live(monkeypatch, fake, cache=None)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 5
    assert fake.max_inflight >= 2


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_rate_limited_predictions_dont_break_scan(tmp_path, monkeypatch):
    """RateLimitExceeded on predict fetches degrades to empty predictions;
    the scan still persists the (bundle-enriched) hypotheses."""
    fake = _FakeLiveClient("test-key")
    fake.predict_error = RateLimitExceeded(60.0)
    _patch_live(monkeypatch, fake, cache=None)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 5
    rows = list_hypotheses(tenant_id="finance")
    assert rows
    for row in rows:
        assert row.predicted_next_techniques == []
        assert row.related_threats == ["Kasablanka", "Sandworm"]


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_basis_filter_keeps_only_attack_flow(tmp_path, monkeypatch):
    """mitre_canonical and blended entries stay out of the persisted field."""
    fake = _FakeLiveClient("test-key")
    _patch_live(monkeypatch, fake, cache=None)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 5
    for row in list_hypotheses(tenant_id="finance"):
        assert len(row.predicted_next_techniques) == 1
        item = row.predicted_next_techniques[0]
        assert item["basis"] == "attack_flow"
        assert item["name"].startswith("Next after")
        assert item["probability"] == 0.85


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_predict_failure_does_not_break_scan(tmp_path, monkeypatch):
    """ThreadlinqsClientError on predict fetches leaves predictions empty but
    bundle enrichment intact and the scan reported normally."""
    fake = _FakeLiveClient("test-key")
    fake.predict_error = ThreadlinqsClientError("prediction endpoint down")
    _patch_live(monkeypatch, fake, cache=None)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["threats_scanned"] == 1
    assert report["generated"] == 5
    for row in list_hypotheses(tenant_id="finance"):
        assert row.predicted_next_techniques == []
        assert row.related_threats


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_09b_client_without_predict_method_is_pass_through(tmp_path, monkeypatch):
    """A client exposing only the bundle seam (no predict_mitre_transitions)
    enriches bundles and leaves predictions empty — no exception."""
    fake = _BundleOnlyClient("test-key")
    _patch_live(monkeypatch, fake, cache=None)

    report = await scan_feed(
        fetch_recent=_mock_use_feed_recent,
        bundle_loader=_mock_bundle_loader,
        rules_path=_RULES_YAML,
        tenants=[require_tenant("finance")],
        store_path=tmp_path / "hypotheses.json",
        enrich=True,
    )
    assert report["generated"] == 5
    assert fake.bundle_calls == [("TL-2026-1693", 3, 25)]
    for row in list_hypotheses(tenant_id="finance"):
        assert row.related_threats == ["Kasablanka"]
        assert row.predicted_next_techniques == []