"""M6.5 — weighted sector relevance for the five client tenants.

Additive change to ``score_threat``: tenants with a ``sector_weights`` map
score related sectors fractionally (primary weight / max weight) so strict
non-matching sectors no longer zero out for adjacent sectors (e.g. a nuclear
threat scores full for the nuclear tenant, an energy threat scores half).
Legacy tenants without the map keep the binary match.
"""

from __future__ import annotations

from app.services.relevance_scorer import score_threat

NUCLEAR = {
    "id": 4,
    "name": "nuclear",
    "sector": "nuclear",
    "geo": "KZ/RU",
    "sector_weights": {"nuclear": 40, "energy": 20},
    "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
    "drl_matrix": {},
}


def test_primary_sector_scores_full():
    threat = {"sectors": ["nuclear"], "regions": ["Global"], "ttps": [], "iocs": []}
    result = score_threat(threat, NUCLEAR)
    assert "nuclear" in result.matching_sectors
    assert result.matching_sectors == ["nuclear"]
    assert result.score == 50.0  # sector_weight 30 + region_weight 20


def test_adjacent_energy_sector_scores_half():
    threat = {"sectors": ["energy"], "regions": ["Global"], "ttps": [], "iocs": []}
    result = score_threat(threat, NUCLEAR)
    assert "energy" in result.matching_sectors
    # 20/40 of sector_weight 30 = half of full sector score.
    assert result.score == round(30.0 / 2.0 + 20.0, 1)


def test_nuclear_ranks_above_energy_for_nuclear_tenant():
    """Objective: the coverage analyzer must rank threats correctly per tenant."""
    nuclear = score_threat({"sectors": ["nuclear"], "regions": ["Global"], "ttps": [], "iocs": []}, NUCLEAR)
    energy = score_threat({"sectors": ["energy"], "regions": ["Global"], "ttps": [], "iocs": []}, NUCLEAR)
    assert nuclear.score > energy.score
    assert energy.zone == "green"


def test_unrelated_sector_scores_zero():
    threat = {"sectors": ["finance"], "regions": [], "ttps": [], "iocs": []}
    result = score_threat(threat, NUCLEAR)
    assert result.matching_sectors == []
    assert result.score == 0.0


def test_legacy_tenant_keeps_binary_match():
    tenant = {
        "id": 2,
        "name": "energy",
        "sector": "energy",
        "geo": "KZ",
        "relevance_config": {"sector_weight": 30, "region_weight": 20, "ttp_weight": 35, "ioc_weight": 15},
        "drl_matrix": {},
    }
    match = score_threat({"sectors": ["energy"], "regions": [], "ttps": [], "iocs": []}, tenant)
    assert len(match.matching_sectors) == 1
    miss = score_threat({"sectors": ["finance"], "regions": [], "ttps": [], "iocs": []}, tenant)
    assert miss.matching_sectors == []