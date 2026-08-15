"""M6.3, ticket 05 — management summary route.

Gated behind the ``management_enabled`` feature flag and RBAC
``management:view`` (module ``management``). Backed entirely by the
deterministic orchestrator; additive only, no shared state, no DB rows.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.core.config import settings
from app.schemas.management import ManagementSummary
from app.services import management_service
from app.services.auth import TeamUser, require_module_permission

router = APIRouter(tags=["Management"])


def _require_enabled(threat_id: str) -> None:
    """Feature gate: refuse with 404 unless the operator enabled the module
    and (offline) the requested threat is the canonical one."""
    if not settings.management_enabled:
        raise HTTPException(404, "Management module is disabled")
    if not settings.threadlinqs_enabled and threat_id != management_service.DEFAULT_THREAT_ID:
        raise HTTPException(
            404,
            "Unknown threat offline: %s (live Threadlinqs integration disabled)"
            % threat_id,
        )


@router.get("/management/summary", response_model=ManagementSummary)
async def summary(
    threat_id: str = management_service.DEFAULT_THREAT_ID,
    tenant_id: str | None = None,
    user: TeamUser = Depends(require_module_permission("management", "management:view")),
) -> ManagementSummary:
    """Return the Russian BLUF summary + priority-sorted hunt hypotheses."""
    _require_enabled(threat_id)
    return await management_service.summary(
        threat_id=threat_id,
        tenant_id=tenant_id,
    )