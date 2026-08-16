# 08 — MCP enricher (bundles)

**Type:** task
**Status:** resolved
**Blocked by:** 04, 06, 07

**What to build:** The one new enrichment seam: a pure, batched function that
decorates Hypotheses with related threats, adversary playbooks, and
infrastructure pivots from `get_threat_hunting_bundle`. It returns new
Hypothesis objects via `model_copy`, never mutates the input list, and is a
pass-through when the MCP is unavailable — so the hunt pipeline never breaks
when Threadlinqs is down.

**Acceptance criteria:**

- [x] New module `app/services/threadlinqs_mcp_enricher.py` exposing
      `enrich_hypotheses(hypotheses, client) -> list[Hypothesis]` (HC-1):
      pure; returns new objects via `model_copy`; input list never mutated.
- [x] Batched (HC-2): exactly one `get_threat_hunting_bundle(threat_id,
      simulation_limit=3, pivot_limit=25)` call per unique `threat_id` in the
      input; results map back onto the hypotheses by `threat_id`.
- [x] The Hypothesis schema in `app/schemas/hypothesis.py` gains
      `related_threats: list[str] = []`, `adversary_playbooks: list[str] = []`,
      `infrastructure_pivots: list[dict] = []` (optional, defaults — no
      migration).
- [x] `adversary_playbooks` enriches `expected_evidence_ru`; `infrastructure_pivots`
      supplements IOCs (never replaces them); `related_threats` is carried as a
      display field.
- [x] Pass-through (HC-2): `_breaker.open`, `threadlinqs_enabled=False`, or
      timeout → returns the input list unchanged (same objects), never an
      exception.
- [x] Orchestration: `scan_feed` calls `enrich_hypotheses` immediately after
      `generate_hypotheses` (client already in scope there); `generate_hypotheses`
      itself stays pure.
- [x] Unit tests `tests/unit/test_mcp_enricher.py` with a `FakeThreadlinqsClient`:
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

## Answer

Ticket 08 is complete.

- **Seam** — new `app/services/threadlinqs_mcp_enricher.py` exposing
  `enrich_hypotheses(hypotheses, client) -> list[Hypothesis]`:
  - pure: enriched hypotheses are NEW objects via `model_copy(update=...)`;
    the input list is never mutated (only read); unenriched rows keep their
    exact original objects; when nothing changed the input list itself is
    returned (same object).
  - batched: one `get_threat_hunting_bundle(threat_id, simulation_limit=3,
    pivot_limit=25)` per unique non-empty `threat_id` (first-seen order via
    `dict.fromkeys`), envelopes map back onto hypotheses by `threat_id` —
    duplicate threat rows share one MCP call.
  - pass-through: `_INTEGRATION_ERRORS` tuple
    `(ThreadlinqsClientError, CircuitOpenError, RateLimitExceeded,
    asyncio.TimeoutError, McpError)` → envelope treated as unavailable; an
    envelope is enrichable only when `_has_enrichment_keys` finds one of
    `similar_threats`/`simulations`/`infrastructure_pivots` at depth-1 or
    under `data` (mirrors the normalizer's own `data`-fallback convention, so
    degraded `{}` responses and bundles with no enrichment block pass through
    as the same objects, never an exception).
- **Extraction** — reuses the Ticket 07 `normalize_bundle` seam (exactly one
  envelope-reading + text-drain place): `related_threats`,
  `adversary_playbooks`, `infrastructure_pivots` ride straight from
  `NormalizedThreat`. `adversary_playbooks` also enriches
  `expected_evidence_ru` with an idempotent single append
  (`"{text} adversary playbooks: {joined}."`, skipped when the phrase is
  already present — double-enrichment of the same seam is a no-op).
- **Schema** — three `default_factory=list` fields appended to
  `app/schemas/hypothesis.py` behind a `# Ticket 08 (M6.4)` comment block:
  `related_threats`, `adversary_playbooks`, `infrastructure_pivots`; no
  migration, absent JSON keys read as `[]`.
- **Orchestration** — `scan_feed` imports `enrich_hypotheses` inside the
  existing `if live:` lazy-import block and calls it immediately after
  `generate_hypotheses` when `client is not None`; offline scans (client
  `None`) skip the seam and stay byte-identical to the pure path (pinned by
  the untouched offline integration tests). `generate_hypotheses` itself is
  untouched.
- **Evidence** — red phase 25/25 failed (`NotImplementedError`, clean
  collection); targeted **25/25 green** (`tests/unit/test_mcp_enricher.py`);
  new live-path integration test in `tests/integration/test_feed_scanner.py`
  (fake live client, one batched call `("TL-2026-1693", 3, 25)`, all three
  fields + evidence phrase asserted on persisted rows) — scanner suite
  **4/4 green**; full backend regression **1139 passed, 11 skipped** in
  95.65s; `ruff check` clean on all changed files (the lone `ASYNC230` lives
  in `scripts/coverage_live_smoke.py`, a pre-existing untouched file).
  Pre-existing `ruff format` drift on untouched lines only — CI gates on
  `ruff check .`.
