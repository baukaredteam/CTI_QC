# 09 — Predicted next techniques (transitions)

**Type:** task
**Status:** ready-for-agent
**Blocked by:** 06, 08

**What to build:** Predicted next techniques for each Hypothesis via
`predict_mitre_transitions`, cache-friendly and rate-limited. The UI shows
only analyst-authored (`attack_flow`-basis) predictions; raw `mitre_canonical`
/ `blended` predictions stay in the raw output. When the MCP or cache is
unavailable, the field is simply empty.

**Acceptance criteria:**

- [ ] The Hypothesis schema in `app/schemas/hypothesis.py` gains
      `predicted_next_techniques: list[dict] = []` (optional, default — no
      migration); each item is `{technique_id, name, probability, basis}`.
- [ ] Batched (HC-2): exactly one `predict_mitre_transitions(technique_id,
      direction='forward', top_n=5, basis='any')` call per unique
      `technique_id` in the input; calls run in batches of 20 in parallel;
      MCP timeout 5s.
- [ ] Cache: `ThreadlinqsCache.get_technique` hit → no MCP call; miss →
      MCP call then `put_technique` with TTL 7 days (`tl:technique:*`); the
      daily rate limiter (5000/day) is respected.
- [ ] Basis filtering: `attack_flow` predictions are surfaced (UI-ready);
      `mitre_canonical` and `blended` are kept in the raw output only.
- [ ] Fallback: `_breaker.open`, `threadlinqs_enabled=False`, or timeout →
      empty `predicted_next_techniques` on each hypothesis, no exception.
- [ ] Unit tests `tests/unit/test_mcp_enricher.py` (extended): cache-hit
      performs no MCP call; miss performs one call per unique technique;
      basis filtering keeps only `attack_flow` for the UI-facing projection.

**Tests:** `tests/unit/test_mcp_enricher.py` with `FakeThreadlinqsClient`
(cache-hit/miss, basis filter). Real-client behavior covered by ticket 11.

**ADDITIVE-ONLY:** appended field + appended batched/cached call in the
enricher; existing client/cache logic is untouched.

**Serialization note:** this is the third of three tickets appending fields to
the Hypothesis schema (04 → 08 → 09). Land in order to avoid conflicting
appends.
