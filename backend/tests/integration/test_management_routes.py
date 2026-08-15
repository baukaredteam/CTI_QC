"""M6.3, ticket 05 — integration tests for GET /api/management/summary.

Thin route-wiring checks over the existing httpx client fixture, matching the
sibling route tests (``test_retrohunt_routes.py``, ``test_rbac_groups.py``):

- module disabled (``management_enabled`` false) -> route absent (404);
- module enabled + auth on + user without ``management:view`` -> 403;
- module enabled + auth on + user with ``management:view`` -> 200 with the
  orchestrator's ManagementSummary shape.

No LLM, no DB rows, offline fixtures only.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.services.auth import TeamUser, current_user


@pytest.mark.asyncio
async def test_summary_route_404_when_module_disabled(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "management_enabled", False)
    response = await client.get(
        "/api/management/summary",
        params={"threat_id": "TL-2026-1693"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_summary_route_404_unknown_threat_offline(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "management_enabled", True)
    monkeypatch.setattr(settings, "threadlinqs_enabled", False)
    response = await client.get(
        "/api/management/summary",
        params={"threat_id": "TL-9999-9999"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_summary_requires_management_view_permission(app, client: AsyncClient, monkeypatch):
    async def denied_user() -> TeamUser:
        return TeamUser(
            name="analyst",
            roles=["analyst"],
            permissions=["read", "run_analysis"],
            modules=["management"],
        )

    monkeypatch.setattr(settings, "management_enabled", True)
    monkeypatch.setattr(settings, "auth_enabled", True)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = denied_user
    try:
        response = await client.get(
            "/api/management/summary",
            params={"threat_id": "TL-2026-1693"},
        )
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_summary_route_returns_orchestrator_shape_with_permission(
    app, client: AsyncClient, monkeypatch
):
    async def allowed_user() -> TeamUser:
        return TeamUser(
            name="soc-manager",
            roles=["analyst"],
            permissions=["read", "run_analysis", "management:view"],
            modules=["management"],
        )

    monkeypatch.setattr(settings, "management_enabled", True)
    monkeypatch.setattr(settings, "auth_enabled", True)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = allowed_user
    try:
        response = await client.get(
            "/api/management/summary",
            params={"threat_id": "TL-2026-1693", "tenant_id": "finance"},
        )
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert response.status_code == 200
    body = response.json()
    # Orchestrator's ManagementSummary shape.
    for key in ("threat_id", "bluf_ru", "status_counts", "tactic_coverage", "hypotheses"):
        assert key in body
    assert body["threat_id"] == "TL-2026-1693"
    assert isinstance(body["hypotheses"], list)
    assert "Сводка" in body["bluf_ru"]