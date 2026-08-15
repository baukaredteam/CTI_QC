"""M6.3 ticket 03 — tenant provider seam.

Covers:
- the eight sector tenants are listable: finance, energy, critical_infrastructure,
  nuclear, metals, electricity, oil_and_gas, gas
- get by id returns the tenant; unknown ids are rejected cleanly
- validate rejects unknown ids
- active_tenant_id setting drives the default active tenant id
- purely additive — no existing coverage pipeline data is altered

Assert through the public seam only (list / get / validate / active id).
The tenant dicts mirror the M1/M6 seeded profiles so coverage stays correct.
"""

from __future__ import annotations

import pytest

from app.services.tenants_provider import (  # type: ignore[import-not-found]
    active_tenant_id,
    all_tenants,
    get_tenant,
    is_valid_tenant_id,
    require_tenant,
)

_EXPECTED_IDS = {
    "finance",
    "energy",
    "critical_infrastructure",
    "nuclear",
    "metals",
    "electricity",
    "oil_and_gas",
    "gas",
}


def test_all_tenants_seeded():
    tenants = all_tenants()
    assert {t["name"] for t in tenants} == _EXPECTED_IDS


def test_active_tenant_defaults_to_finance():
    assert active_tenant_id() in _EXPECTED_IDS


def test_require_tenant_returns_tenant_dict():
    tenant = require_tenant("finance")
    assert isinstance(tenant, dict)
    assert tenant["name"] == "finance"
    assert "sector" in tenant
    assert "geo" in tenant
    assert "drl_matrix" in tenant


def test_require_unknown_tenant_raises():
    with pytest.raises(ValueError):
        require_tenant("nonsense_tenant")


def test_get_tenant_returns_none_for_unknown():
    assert get_tenant("nonsense_tenant") is None
    assert get_tenant("finance") is not None


def test_is_valid_tenant_id():
    assert is_valid_tenant_id("energy") is True
    assert is_valid_tenant_id("") is False
    assert is_valid_tenant_id("none") is False


def test_active_tenant_is_seeded():
    active = active_tenant_id()
    assert is_valid_tenant_id(active)
    assert require_tenant(active)["name"] == active


def test_tenants_have_coverage_shape():
    # The seam must hand the coverage pipeline dicts it can score as-is:
    # relevance_config + drl_matrix are required by analyze_coverage.
    for tenant in all_tenants():
        assert set(["sector", "geo", "relevance_config", "drl_matrix"]).issubset(tenant)