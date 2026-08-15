"""Inline tenant provider seam — M6.3, ticket 03. Pure data, no I/O.

Exposes the seeded sector tenants (finance, energy, critical_infrastructure)
plus the five real client sectors (nuclear, metals, electricity, oil_and_gas,
gas) and an ``active_tenant_id`` setting that drives the default tenant
context. Consumers get deterministic list / get / validate / require
behaviour keyed by tenant id, so coverage is always tenant-correct. M5 swaps
these inline profiles for DB-backed tenants without changing the service
signature.

The five client tenants carry a ``sector_weights`` map (canonical sector →
relative weight) used by ``score_threat`` for ranked sector relevance:
their own sector scores full (weight/max), the adjacent ``energy`` sector
scores partial. The three seeded tenants keep the legacy binary match.
"""

from __future__ import annotations

from typing import Any

from app.core.config import settings

# Inline tenant profiles — the exact M1/M6.1 smoke profiles. None has a
# sysmon key, so every sysmon_required rule is SYSMON_BLIND for all three.
_TENANTS: list[dict[str, Any]] = [
    {
        "id": 1,
        "name": "finance",
        "sector": "finance",
        "geo": "KZ",
        "relevance_config": {
            "sector_weight": 30,
            "region_weight": 20,
            "ttp_weight": 35,
            "ioc_weight": 15,
        },
        "drl_matrix": {"windows_event_log": 3, "proxy_log": 2, "email_gateway": 1},
    },
    {
        "id": 2,
        "name": "energy",
        "sector": "energy",
        "geo": "KZ",
        "relevance_config": {
            "sector_weight": 30,
            "region_weight": 20,
            "ttp_weight": 35,
            "ioc_weight": 15,
        },
        "drl_matrix": {"windows_event_log": 4, "proxy_log": 3, "email_gateway": 3},
    },
    {
        "id": 3,
        "name": "critical_infrastructure",
        "sector": "critical_infrastructure",
        "geo": "KZ",
        "relevance_config": {
            "sector_weight": 30,
            "region_weight": 20,
            "ttp_weight": 35,
            "ioc_weight": 15,
        },
        "drl_matrix": {"windows_event_log": 1, "proxy_log": 0, "email_gateway": 0},
    },
    # — M6.5 real client sectors (Казатомпром/Росатом, Северсталь/НЛМК/ММК,
    #   Россети/ФСК ЕЭС, Газпром/Роснефть/Лукойл). Weighted sector relevance:
    #   primary sector scores full, adjacent energy scores partial.
    {
        "id": 4,
        "name": "nuclear",
        "sector": "nuclear",
        "geo": "KZ/RU",
        "sector_weights": {"nuclear": 40, "energy": 20},
        "relevance_config": {
            "sector_weight": 30,
            "region_weight": 20,
            "ttp_weight": 35,
            "ioc_weight": 15,
        },
        "drl_matrix": {"windows_event_log": 3, "proxy_log": 2, "email_gateway": 1},
    },
    {
        "id": 5,
        "name": "metals",
        "sector": "metals",
        "geo": "RU",
        "sector_weights": {"metals": 40, "energy": 15},
        "relevance_config": {
            "sector_weight": 30,
            "region_weight": 20,
            "ttp_weight": 35,
            "ioc_weight": 15,
        },
        "drl_matrix": {"windows_event_log": 3, "proxy_log": 2, "email_gateway": 1},
    },
    {
        "id": 6,
        "name": "electricity",
        "sector": "electricity",
        "geo": "RU",
        "sector_weights": {"electricity": 40, "energy": 20},
        "relevance_config": {
            "sector_weight": 30,
            "region_weight": 20,
            "ttp_weight": 35,
            "ioc_weight": 15,
        },
        "drl_matrix": {"windows_event_log": 4, "proxy_log": 3, "email_gateway": 2},
    },
    {
        "id": 7,
        "name": "oil_and_gas",
        "sector": "oil_and_gas",
        "geo": "RU",
        "sector_weights": {"oil_and_gas": 40, "energy": 15},
        "relevance_config": {
            "sector_weight": 30,
            "region_weight": 20,
            "ttp_weight": 35,
            "ioc_weight": 15,
        },
        "drl_matrix": {"windows_event_log": 4, "proxy_log": 3, "email_gateway": 2},
    },
    {
        "id": 8,
        "name": "gas",
        "sector": "gas",
        "geo": "RU",
        "sector_weights": {"gas": 40, "energy": 15},
        "relevance_config": {
            "sector_weight": 30,
            "region_weight": 20,
            "ttp_weight": 35,
            "ioc_weight": 15,
        },
        "drl_matrix": {"windows_event_log": 3, "proxy_log": 2, "email_gateway": 2},
    },
]

_TENANT_BY_ID: dict[str, dict[str, Any]] = {t["name"]: t for t in _TENANTS}


def all_tenants() -> list[dict[str, Any]]:
    """Return the seeded tenant profiles as fresh dicts (listable)."""
    return [dict(t) for t in _TENANTS]


def get_tenant(tenant_id: str) -> dict[str, Any] | None:
    """Return a fresh copy of the tenant profile for ``tenant_id`` or None."""
    profile = _TENANT_BY_ID.get(tenant_id)
    return dict(profile) if profile is not None else None


def require_tenant(tenant_id: str) -> dict[str, Any]:
    """Return the tenant profile, raising ValueError for unknown ids."""
    tenant = get_tenant(tenant_id)
    if tenant is None:
        raise ValueError("Unknown tenant: %s" % tenant_id)
    return tenant


# Backward-compatible alias: the acceptance contract historically referred
# to the seam as ``require_valid_tenant``; both names work.
require_valid_tenant = require_tenant


def is_valid_tenant_id(tenant_id: str) -> bool:
    """Return True only for a known tenant id."""
    return tenant_id in _TENANT_BY_ID


def active_tenant_id() -> str:
    """The id of the currently active tenant from settings."""
    return settings.active_tenant_id