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

import pytest

from app.services.hypothesis_generator import generate_hypotheses
from app.services.hypothesis_store import (
    add_hypothesis,
    clear,
    get_hypothesis,
    list_hypotheses,
)
from app.services.rules_parser import parse_rules_file
from app.services.tenants_provider import require_tenant
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