"""M6.4 — integration tests for GET/PATCH /api/hypotheses.

Thin route-wiring checks over the existing httpx client fixture, matching the
sibling route tests (``test_management_routes.py``, ``test_retrohunt_routes.py``):

- module disabled (``hypothesis_enabled`` false) -> route absent (404);
- module enabled + auth on + user without ``hypothesis:view`` -> 403;
- user with ``hypothesis:view`` -> 200 listing stored hypotheses;
- PATCH advances a proposed hypothesis to validated (lifecycle).

No LLM, no DB rows, offline fixtures only.
"""

from __future__ import annotations

import pathlib

import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.schemas.hypothesis import Hypothesis
from app.services.auth import TeamUser, current_user
from app.services.hypothesis_generator import generate_hypotheses
from app.services.hypothesis_store import add_hypothesis, clear
from app.services.rules_parser import parse_rules_file
from app.services.tenants_provider import require_tenant

_RULES_YAML = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "full_rules85.yaml"

_BUNDLE = {
    "id": "TL-2026-1693",
    "title": "Sauri",
    "sectors": ["finance"],
    "regions": ["Global"],
    "ttps": ["T1486"],
    "iocs": [],
    "actor_confidence": "high",
}


def _rules():
    return parse_rules_file(_RULES_YAML).rules


def _seed(monkeypatch, tmp_path) -> Hypothesis:
    monkeypatch.setattr(
        "app.services.hypothesis_store._DEFAULT_FILE",
        tmp_path / "hypotheses.json",
    )
    clear()
    row = generate_hypotheses(
        threat_id="TL-2026-1693",
        bundle=_BUNDLE,
        tenant=require_tenant("finance"),
        rules=_rules(),
        max_hypotheses=1,
    )[0]
    add_hypothesis(row)
    return row


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="full_rules85.yaml fixture not present")
async def test_list_route_404_when_module_disabled(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "hypothesis_enabled", False)
    response = await client.get("/api/hypotheses")
    assert response.status_code == 404


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="fixtures present")
async def test_requires_hypothesis_view_permission(app, client: AsyncClient, monkeypatch):
    async def denied_user() -> TeamUser:
        return TeamUser(
            name="analyst",
            roles=["analyst"],
            permissions=["read", "run_analysis"],
            modules=["hypothesis"],
        )

    monkeypatch.setattr(settings, "hypothesis_enabled", True)
    monkeypatch.setattr(settings, "auth_enabled", True)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = denied_user
    try:
        response = await client.get("/api/hypotheses")
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert response.status_code == 403


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="fixtures present")
async def test_list_and_validate_flow(app, client: AsyncClient, monkeypatch, tmp_path):
    row = _seed(monkeypatch, tmp_path)

    async def allowed_user() -> TeamUser:
        return TeamUser(
            name="soc-manager",
            roles=["analyst"],
            permissions=["read", "run_analysis", "hypothesis:view", "hypothesis:validate"],
            modules=["hypothesis"],
        )

    monkeypatch.setattr(settings, "hypothesis_enabled", True)
    monkeypatch.setattr(settings, "auth_enabled", True)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = allowed_user
    try:
        listed = await client.get("/api/hypotheses")
        assert listed.status_code == 200
        body = listed.json()
        assert isinstance(body, list)
        assert any(item["id"] == row.id for item in body)

        patched = await client.patch(f"/api/hypotheses/{row.id}", json={"status": "validated"})
        assert patched.status_code == 200
        assert patched.json()["status"] == "validated"
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="fixtures present")
async def test_patch_requires_hypothesis_validate_permission_spec_gap(
    app, client: AsyncClient, monkeypatch, tmp_path
):
    """Red for STEP 5 gap: PATCH must be gated by ``hypothesis:validate``,
    not the read ``hypothesis:view`` used by GET. A view-only user must get 403."""
    row = _seed(monkeypatch, tmp_path)

    async def view_only_user() -> TeamUser:
        return TeamUser(
            name="soc-manager",
            roles=["analyst"],
            permissions=["read", "run_analysis", "hypothesis:view"],
            modules=["hypothesis"],
        )

    monkeypatch.setattr(settings, "hypothesis_enabled", True)
    monkeypatch.setattr(settings, "auth_enabled", True)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = view_only_user
    try:
        response = await client.patch(f"/api/hypotheses/{row.id}", json={"status": "validated"})
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert response.status_code == 403


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="fixtures present")
async def test_scan_route_404_when_module_disabled(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "hypothesis_enabled", False)
    response = await client.post("/api/hypotheses/scan")
    assert response.status_code == 404


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="fixtures present")
async def test_scan_requires_hypothesis_validate_permission(
    app, client: AsyncClient, monkeypatch, tmp_path
):
    """The scan trigger mutates the store, so it must be gated by ``hypothesis:validate``,
    not the read-only list permission."""
    _seed(monkeypatch, tmp_path)

    async def view_only_user() -> TeamUser:
        return TeamUser(
            name="soc-manager",
            roles=["analyst"],
            permissions=["read", "run_analysis", "hypothesis:view"],
            modules=["hypothesis"],
        )

    monkeypatch.setattr(settings, "hypothesis_enabled", True)
    monkeypatch.setattr(settings, "auth_enabled", True)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = view_only_user
    try:
        response = await client.post("/api/hypotheses/scan")
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert response.status_code == 403


@pytest.mark.skipif(not _RULES_YAML.exists(), reason="fixtures present")
async def test_scan_runs_feed_scanner(app, client: AsyncClient, monkeypatch, tmp_path):
    """M6.5 STEP 1: a validate-capable user triggers the scanner and gets its report."""
    monkeypatch.setattr(
        "app.services.hypothesis_store._DEFAULT_FILE",
        tmp_path / "hypotheses.json",
    )
    clear()

    async def allowed_user() -> TeamUser:
        return TeamUser(
            name="soc-manager",
            roles=["analyst"],
            permissions=["read", "run_analysis", "hypothesis:view", "hypothesis:validate"],
            modules=["hypothesis"],
        )

    monkeypatch.setattr(settings, "hypothesis_enabled", True)
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "threadlinqs_enabled", False)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = allowed_user
    try:
        response = await client.post("/api/hypotheses/scan")
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert response.status_code == 200
    report = response.json()
    assert report["threats_scanned"] >= 1
    assert report["generated"] >= 1