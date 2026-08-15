# 08 — MCP enricher (bundles)

**Type:** task
**Status:** ready-for-agent
**Blocked by:** 04, 06, 07

**What to build:** The one new enrichment seam: a pure, batched function that
decorates Hypotheses with related threats, adversary playbooks, and
infrastructure pivots from `get_threat_hunting_bundle`. It returns new
Hypothesis objects via `model_copy`, never mutates the input list, and is a
pass-through when the MCP is unavailable — so the hunt pipeline never breaks
when Threadlinqs is down.

**Acceptance criteria:**

- [ ] New module `app/services/threadlinqs_mcp_enricher.py` exposing
      `enrich_hypotheses(hypotheses, client) -> list[Hypothesis]` (HC-1):
      pure; returns new objects via `model_copy`; input list never mutated.
- [ ] Batched (HC-2): exactly one `get_threat_hunting_bundle(threat_id,
      simulation_limit=3, pivot_limit=25)` call per unique `threat_id` in the
      input; results map back onto the hypotheses by `threat_id`.
- [ ] The Hypothesis schema in `app/schemas/hypothesis.py` gains
      `related_threats: list[str] = []`, `adversary_playbooks: list[str] = []`,
      `infrastructure_pivots: list[dict] = []` (optional, defaults — no
      migration).
- [ ] `adversary_playbooks` enriches `expected_evidence_ru`; `infrastructure_pivots`
      supplements IOCs (never replaces them); `related_threats` is carried as a
      display field.
- [ ] Pass-through (HC-2): `_breaker.open`, `threadlinqs_enabled=False`, or
      timeout → returns the input list unchanged (same objects), never an
      exception.
- [ ] Orchestration: `scan_feed` calls `enrich_hypotheses` immediately after
      `generate_hypotheses` (client already in scope there); `generate_hypotheses`
      itself stays pure.
- [ ] Unit tests `tests/unit/test_mcp_enricher.py` with a `FakeThreadlinqsClient`:
      happy path mapping, one-call-per-threat batching, non-mutation, and
      pass-through fallback.

**Tests:** `tests/unit/test_mcp_enricher.py` (FakeThreadlinqsClient); real
client covered by ticket 11 (integration, MCP on/off). Prior art:
`test_m6_coverage.py` style — no DB.

**ADDITIVE-ONLY:** new module + appended schema fields + appended orchestration
line in `scan_feed`; the working client/cache/normalizer and the generator's
existing path are untouched.

**Serialization note:** this is the second of three tickets appending fields to
the Hypothesis schema (04 → 08 → 09). Land in order to avoid conflicting
appends.
