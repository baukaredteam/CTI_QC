"""M6.4 — MCP bundle enricher (Ticket 08) test suite.

Pure-unit, no DB (``test_m6_coverage.py`` style): a ``FakeThreadlinqsClient``
stands in for the live MCP seam, so batching, pass-through, and field
decoration are exercised deterministically offline. The real client's
on/off behavior is covered by ticket 11 integration tests.
"""

from __future__ import annotations

import asyncio

import pytest

from app.schemas.hypothesis import Hypothesis, HypothesisIOC
from app.schemas.management import AdmiraltyOut
from app.services.circuit_breaker import CircuitOpenError
from app.services.rate_limiter import RateLimitExceeded
from app.services.threadlinqs_client import ThreadlinqsClientError
from app.services.threadlinqs_mcp_enricher import enrich_hypotheses

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_GAP_EVIDENCE_RU = (
    "Ожидаемые свидетельства техники T1078 (Valid Accounts, тактика «persistence»): "
    "корреляция в телеметрии по полям qid, eventid. "
    "Требуется авторство нового покрывающего правила."
)


def _hypothesis(threat_id: str = "TL-2026-1693", technique_id: str = "T1078") -> Hypothesis:
    return Hypothesis(
        id=f"{threat_id}:{technique_id}",
        threat_id=threat_id,
        tenant_id="finance",
        technique_id=technique_id,
        technique_name="Valid Accounts",
        tactic="persistence",
        priority=5.0,
        zone="east",
        status="proposed",
        coverage_status="COVERAGE_GAP",
        coverage_status_ru="нет покрывающего правила",
        admiralty=AdmiraltyOut(letter="C", digit="3", rationale_ru="тест"),
        expected_evidence_ru=_GAP_EVIDENCE_RU,
        text_ru="Гипотеза T1078: нет покрывающего правила.",
        threat_title="Sauri",
        threat_summary="Sauri",
        iocs=[HypothesisIOC(ioc_type="domain", value="evil.example", note_ru="вредоносный — тест.")],
    )


def _envelope(
    threat_id: str = "TL-2026-1693",
    *,
    related: bool = True,
    playbooks: bool = True,
    pivots: bool = True,
) -> dict:
    env: dict = {"id": threat_id, "title": "Sauri"}
    if related:
        env["similar_threats"] = [{"name": "Kasablanka"}, {"name": "Sandworm"}]
    if playbooks:
        env["simulations"] = [{"playbook": "Port Scan"}, {"playbook": "C2 Beacon"}]
    if pivots:
        env["infrastructure_pivots"] = [{"ipv4": "203.0.113.7", "asn": "AS1234"}]
    return env


class FakeThreadlinqsClient:
    """Records calls; serves per-threat envelopes or per-threat exceptions."""

    def __init__(
        self,
        bundles: dict[str, dict] | None = None,
        *,
        absent_method: bool = False,
        errors: dict[str, Exception] | None = None,
        non_dict: bool = False,
    ) -> None:
        self.bundles = dict(bundles or {})
        self.errors = dict(errors or {})
        self.absent_method = absent_method
        self.non_dict = non_dict
        self.calls: list[tuple] = []
        if absent_method:
            # Shadow the class method so the seam's callable guard is hit.
            self.get_threat_hunting_bundle = None  # type: ignore[assignment]

    async def get_threat_hunting_bundle(
        self,
        threat_id: str,
        simulation_limit: int = 3,
        pivot_limit: int = 25,
    ):
        self.calls.append((threat_id, simulation_limit, pivot_limit))
        exc = self.errors.get(threat_id)
        if exc is not None:
            raise exc
        if self.non_dict:
            return "not-a-dict"
        return self.bundles.get(threat_id, {})

    @property
    def call_count(self) -> int:
        return len(self.calls)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_happy_path_decorates_all_three_fields():
    client = FakeThreadlinqsClient({_envelope()["id"]: _envelope()})
    rows = [_hypothesis(), _hypothesis(technique_id="T1059.001")]
    result = await enrich_hypotheses(rows, client)

    assert len(result) == 2
    assert result[0].related_threats == ["Kasablanka", "Sandworm"]
    assert result[0].adversary_playbooks == ["Port Scan", "C2 Beacon"]
    assert result[0].infrastructure_pivots == [{"ipv4": "203.0.113.7", "asn": "AS1234"}]
    assert result[1].related_threats == ["Kasablanka", "Sandworm"]
    assert result[1].adversary_playbooks == ["Port Scan", "C2 Beacon"]


async def test_happy_path_returns_new_objects_not_the_input():
    client = FakeThreadlinqsClient({_envelope()["id"]: _envelope()})
    rows = [_hypothesis()]
    result = await enrich_hypotheses(rows, client)

    assert result[0] is not rows[0]


async def test_happy_path_preserves_iocs_and_provenance():
    client = FakeThreadlinqsClient({_envelope()["id"]: _envelope()})
    rows = [_hypothesis()]
    result = await enrich_hypotheses(rows, client)

    assert result[0].iocs == rows[0].iocs
    assert result[0].id == rows[0].id
    assert result[0].threat_id == rows[0].threat_id
    assert result[0].technique_id == rows[0].technique_id
    assert result[0].status == "proposed"
    assert result[0].priority == 5.0
    assert result[0].admiralty.letter == "C"


# ---------------------------------------------------------------------------
# Batching — one call per unique threat_id
# ---------------------------------------------------------------------------


async def test_one_call_per_unique_threat_id_with_limits():
    env_a = _envelope("TL-A")
    env_b = _envelope("TL-B")
    client = FakeThreadlinqsClient({"TL-A": env_a, "TL-B": env_b})
    rows = [
        _hypothesis("TL-A", "T1"),
        _hypothesis("TL-B", "T2"),
        _hypothesis("TL-A", "T3"),
    ]
    await enrich_hypotheses(rows, client)

    assert client.call_count == 2
    assert client.calls[0] == ("TL-A", 3, 25)
    assert client.calls[1] == ("TL-B", 3, 25)


async def test_same_envelope_maps_back_to_every_hypothesis_of_a_threat():
    env = _envelope("TL-A")
    client = FakeThreadlinqsClient({"TL-A": env})
    rows = [_hypothesis("TL-A", "T1"), _hypothesis("TL-A", "T2")]
    result = await enrich_hypotheses(rows, client)

    assert client.call_count == 1
    assert result[0].adversary_playbooks == ["Port Scan", "C2 Beacon"]
    assert result[1].adversary_playbooks == ["Port Scan", "C2 Beacon"]


# ---------------------------------------------------------------------------
# Pass-through
# ---------------------------------------------------------------------------


async def test_empty_input_returns_same_object():
    client = FakeThreadlinqsClient()
    rows: list[Hypothesis] = []
    result = await enrich_hypotheses(rows, client)

    assert result is rows
    assert client.call_count == 0


async def test_client_without_method_is_pass_through():
    client = FakeThreadlinqsClient(absent_method=True)
    rows = [_hypothesis()]
    result = await enrich_hypotheses(rows, client)

    assert result is rows
    assert client.call_count == 0


async def test_pass_through_on_empty_envelope():
    client = FakeThreadlinqsClient({})  # get_threat_hunting_bundle returns {}
    rows = [_hypothesis(), _hypothesis("TL-B")]
    result = await enrich_hypotheses(rows, client)

    assert result is rows
    assert result[0] is rows[0]
    assert result[1] is rows[1]
    assert result[0].adversary_playbooks == []


async def test_pass_through_on_non_dict_envelope():
    client = FakeThreadlinqsClient(non_dict=True)
    rows = [_hypothesis()]
    result = await enrich_hypotheses(rows, client)

    assert result[0] is rows[0]


async def test_pass_through_when_envelope_missing_all_enrichment_keys():
    client = FakeThreadlinqsClient({"TL-2026-1693": {"id": "TL-2026-1693", "title": "Sauri"}})
    rows = [_hypothesis()]
    result = await enrich_hypotheses(rows, client)

    assert result[0] is rows[0]
    assert result[0].related_threats == []


async def test_pass_through_leaves_expected_evidence_unchanged():
    client = FakeThreadlinqsClient({})  # offline client -> {}
    rows = [_hypothesis()]
    result = await enrich_hypotheses(rows, client)

    assert result[0].expected_evidence_ru == _GAP_EVIDENCE_RU


@pytest.mark.parametrize(
    "exc",
    [
        ThreadlinqsClientError("down"),
        CircuitOpenError(60.0),
        RateLimitExceeded(60.0),
        asyncio.TimeoutError("t"),
        McpError(ErrorData(code=-32603, message="mcp")),
    ],
)
async def test_pass_through_on_integration_errors(exc):
    client = FakeThreadlinqsClient(errors={"TL-2026-1693": exc})
    rows = [_hypothesis()]
    result = await enrich_hypotheses(rows, client)

    assert result[0] is rows[0]
    assert result[0].adversary_playbooks == []


async def test_partial_enrichment_per_threat():
    client = FakeThreadlinqsClient(
        {
            "TL-A": _envelope("TL-A"),
            "TL-B": {},  # unavailable for this threat only
        }
    )
    rows = [_hypothesis("TL-A", "T1"), _hypothesis("TL-B", "T2")]
    result = await enrich_hypotheses(rows, client)

    assert result[0].related_threats == ["Kasablanka", "Sandworm"]
    assert result[1] is rows[1]


async def test_input_list_never_mutated():
    client = FakeThreadlinqsClient({"TL-A": _envelope("TL-A")})
    rows = [_hypothesis("TL-A", "T1"), _hypothesis("TL-B", "T2")]
    before = list(rows)
    await enrich_hypotheses(rows, client)

    assert rows == before
    assert all(a is b for a, b in zip(rows, before, strict=True))
    assert all(h.related_threats == [] for h in rows)


# ---------------------------------------------------------------------------
# expected_evidence_ru enrichment
# ---------------------------------------------------------------------------


async def test_gap_evidence_appends_playbook_phrase():
    client = FakeThreadlinqsClient({_envelope()["id"]: _envelope()})
    result = await enrich_hypotheses([_hypothesis()], client)

    assert result[0].expected_evidence_ru == (
        f"{_GAP_EVIDENCE_RU} adversary playbooks: Port Scan, C2 Beacon."
    )


async def test_expected_evidence_is_idempotent():
    env = _envelope()
    client = FakeThreadlinqsClient({env["id"]: env})
    rows = [_hypothesis()]
    once = await enrich_hypotheses(rows, client)
    twice = await enrich_hypotheses(once, client)

    assert "adversary playbooks" in once[0].expected_evidence_ru
    assert once[0].expected_evidence_ru == twice[0].expected_evidence_ru


async def test_covered_evidence_appends_playbook_phrase():
    env = _envelope()
    client = FakeThreadlinqsClient({env["id"]: env})
    h = _hypothesis()
    h = h.model_copy(update={"expected_evidence_ru": "Ожидаемые поля/признаки техники T1078; соотносить с правилами: R1."})
    result = await enrich_hypotheses([h], client)

    assert result[0].expected_evidence_ru.endswith(" adversary playbooks: Port Scan, C2 Beacon.")


async def test_empty_playbooks_leave_evidence_unchanged():
    env = _envelope(playbooks=False)  # only similar_threats present
    client = FakeThreadlinqsClient({env["id"]: env})
    rows = [_hypothesis()]
    result = await enrich_hypotheses(rows, client)

    assert result[0].expected_evidence_ru == _GAP_EVIDENCE_RU
    assert result[0].adversary_playbooks == []
    assert result[0].related_threats == ["Kasablanka", "Sandworm"]


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


async def test_enrichment_keys_under_data_fallback():
    env = {"id": "TL-D", "title": "Deep", "data": {"simulations": [{"playbook": "Deep Sim"}]}}
    client = FakeThreadlinqsClient({"TL-D": env})
    result = await enrich_hypotheses([_hypothesis("TL-D")], client)

    assert result[0].adversary_playbooks == ["Deep Sim"]


async def test_related_threats_deduped_and_order_preserved():
    env = _envelope()
    env["similar_threats"] = [{"name": "AAA"}, {"name": "BBB"}, {"name": "AAA"}]
    client = FakeThreadlinqsClient({env["id"]: env})
    result = await enrich_hypotheses([_hypothesis()], client)

    assert result[0].related_threats == ["AAA", "BBB"]


async def test_pivot_scalars_only():
    env = _envelope()
    env["infrastructure_pivots"] = [{"ipv4": "203.0.113.7", "nested": {"x": 1}, "null": None}]
    client = FakeThreadlinqsClient({env["id"]: env})
    result = await enrich_hypotheses([_hypothesis()], client)

    assert result[0].infrastructure_pivots == [{"ipv4": "203.0.113.7"}]