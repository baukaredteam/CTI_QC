"""M6.4 — Hypotheses API route.

Lists persisted hunt hypotheses produced by the ``feed_scanner.scan`` worker
and advances their status (proposed → validated | rejected). List/read are
gated behind the ``hypothesis_enabled`` feature flag and RBAC (module
``hypothesis`` + permission ``hypothesis:view``); the status transition and
the manual scan trigger require the separate ``hypothesis:validate``
permission. Backed by the in-memory + JSON store in ``app.services.hypothesis_store``;
no new DB rows.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.config import settings
from app.schemas.hypothesis import Hypothesis
from app.services import hypothesis_store
from app.services.auth import TeamUser, require_module_permission

router = APIRouter(tags=["Hypotheses"])

VALID_STATUSES = {"proposed", "validated", "rejected"}


class HypothesisStatusUpdate(BaseModel):
    status: str = Field(..., description="New status: validated or rejected")


class ScanReport(BaseModel):
    threats_scanned: int
    generated: int
    skipped: int


def _require_enabled() -> None:
    if not settings.hypothesis_enabled:
        raise HTTPException(404, "Hypothesis module is disabled")


@router.get("/hypotheses", response_model=list[Hypothesis])
async def list_hypotheses(
    tenant_id: str | None = None,
    status: str | None = None,
    threat_id: str | None = None,
    user: TeamUser = Depends(require_module_permission("hypothesis", "hypothesis:view")),
) -> list[Hypothesis]:
    """Return stored hypotheses, optionally filtered by tenant/status/threat."""
    _require_enabled()
    if status is not None and status not in VALID_STATUSES:
        raise HTTPException(400, "Unknown hypothesis status: %s" % status)
    return hypothesis_store.list_hypotheses(
        tenant_id=tenant_id,
        status=status,
        threat_id=threat_id,
    )


@router.post("/hypotheses/scan", response_model=ScanReport)
async def trigger_scan(
    user: TeamUser = Depends(require_module_permission("hypothesis", "hypothesis:validate")),
) -> ScanReport:
    """Run the feed scanner against recent threats and persist new hypotheses.

    Gated by ``hypothesis:validate`` (mutates the store). Uses the live
    Threadlinqs ``get_recent_threats`` feed only when the integration is
    enabled (degrading to the deterministic offline default otherwise) and
    returns the scanned/generated counts.
    """
    _require_enabled()
    from app.tasks.feed_scanner import live_recent_threat_ids, scan_feed

    if settings.threadlinqs_enabled:
        report = await scan_feed(fetch_recent=live_recent_threat_ids, enrich=True)
    else:
        report = await scan_feed(enrich=True)
    return ScanReport(**report)


@router.get("/hypotheses/{hypothesis_id}", response_model=Hypothesis)
async def get_hypothesis(
    hypothesis_id: str,
    user: TeamUser = Depends(require_module_permission("hypothesis", "hypothesis:view")),
) -> Hypothesis:
    """Return one stored hypothesis."""
    _require_enabled()
    row = hypothesis_store.get_hypothesis(hypothesis_id)
    if row is None:
        raise HTTPException(404, "Hypothesis not found")
    return row


@router.patch("/hypotheses/{hypothesis_id}", response_model=Hypothesis)
async def update_hypothesis(
    hypothesis_id: str,
    body: HypothesisStatusUpdate,
    user: TeamUser = Depends(require_module_permission("hypothesis", "hypothesis:validate")),
) -> Hypothesis:
    """Advance a proposed hypothesis to validated or rejected."""
    _require_enabled()
    if body.status not in {"validated", "rejected"}:
        raise HTTPException(400, "Status must be validated or rejected")
    row = hypothesis_store.update_status(hypothesis_id, body.status)
    if row is None:
        raise HTTPException(404, "Hypothesis not found")
    return row