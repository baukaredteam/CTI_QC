# 09B — Live prediction orchestration (decision record)

**Type:** decision
**Status:** resolved (Option A — additive `scan_feed` orchestration)
**Parent:** Ticket 09 `c26b6e6` (discovered during 09.1)
**Blocked by:** none — records a gap; does not block 09.1 delivery

**Question:** should the live feed path populate `predicted_next_techniques`
via `enrich_predictions`, and if so, where does the call live?

## Context

Ticket 11 ("acceptance and smoke") expects a populated
`predicted_next_techniques` field when `threadlinqs_enabled=True`. The
orchestration contradiction:

- `scan_feed` (`backend/app/tasks/feed_scanner.py`) calls only
  `enrich_hypotheses` for Threadlinqs-enabled feeds — it never calls
  `enrich_predictions` (`backend/app/services/threadlinqs_mcp_enricher.py`).
- Evidence from the 09.1 impact scan: production `ThreadlinqsCache` instances
  are constructed at `feed_scanner.py:168` and `management_service.py:491`;
  the only `enrich_predictions` callers are tests.
- Therefore `predicted_next_techniques` will stay empty in live flows even
  after 09.1 fixes technique TTL caching, because the enrichment is simply
  never invoked end-to-end.

09.1 does not wire this (explicitly out of scope). This ticket records the
gap and the recommended resolution so Ticket 11's acceptance criteria can be
honest about what "populated" means.

## Options

- **Option A — additive `scan_feed` orchestration (recommended).** Inside the
  existing Threadlinqs branch of `scan_feed`:
  `generate_hypotheses -> enrich_hypotheses -> enrich_predictions -> add_many`
  (or the equivalent persistence call), sharing one `ThreadlinqsCache` and one
  client between the two enrichment passes, guarded by the same
  `threadlinqs_enabled` flag. Additive: existing behavior unchanged for
  disabled/enabled-other paths; failure of prediction enrichment is logged and
  does not fail the feed.
  - Pros: single feed pass, one MCP client/cache, matches the contract 09
    claimed; small diff.
  - Cons: makes `scan_feed` slightly longer; needs a task-level test
    (integration) that a feed with predictions persists them.
- **Option B — separate enrichment task.** A new Celery task
  (`enrich_predictions_on_hypotheses`) invoked after the feed, or via a new
  route.
  - Pros: keeps `scan_feed` thin; retry/backoff isolated per task.
  - Cons: two passes over the same hypotheses, two cache/client lifetimes,
    more moving parts for a single field; contradicts Ticket 09's stated flow
    shape.
- **Option C — defer and downgrade Ticket 11.** Leave live prediction
  unwired; change Ticket 11 expectation to unit-level only (enricher tests),
  dropping the `threadlinqs_enabled=True -> predicted_next_techniques`
  populated expectation in acceptance/smoke.
  - Pros: zero new code now; honest acceptance.
  - Cons: live users never see predictions; Ticket 09's documented behavior
    remains aspirational in production.

## Recommendation

**Option A.** It is the smallest change that makes `predicted_next_techniques`
truthful in the live path, reuses the exact cache/client 09.1 just hardened,
and keeps the smoke expectations in Ticket 11 achievable. Record the decision
here (flip `Status` to `resolved` with the chosen option) before Ticket 11
implementation begins.

## Resolution

**Chosen: Option A** — additive `scan_feed` orchestration, implemented with
TDD (RED first, then minimal GREEN).

Changes (both additive-only, no behavior change for disabled/offline paths):

- `backend/app/tasks/feed_scanner.py`: lazy import extended to include
  `enrich_predictions`; inside the existing `if client is not None:` branch the
  pipeline is now
  `generate_hypotheses -> enrich_hypotheses -> enrich_predictions -> add_many`,
  sharing the same `ThreadlinqsCache` instance between the two enrichment
  passes. No change to the offline (`client is None`) path — still
  byte-identical to the pure path.
- `backend/tests/integration/test_feed_scanner.py`: 12 new integration tests
  covering: live scans populate `predicted_next_techniques`; offline and
  disabled-feeds stay empty; cache hit skips the MCP call; cache miss ⇒ one
  call per technique + `put`; TTL 7 days; duplicate technique IDs share one
  call; parallel batch fetching; rate-limit and predict-failure degrade to
  pass-through without failing the scan; `basis` filter keeps attack flow only;
  clients without a `predict` method are pass-through.

## Evidence

- RED: 7 new tests failed before the seam call (GREEN on the pass-through /
  offline guards), 9 passed.
- GREEN: all 16 tests in `test_feed_scanner.py` pass (`--no-cov`).
- Full backend regression: **1176 passed, 11 skipped** (baseline 1139 + 25
  tests from 09.1 + 12 from 09B; zero failures).
- `ruff check` clean on both modified files.
- Diff tree: 3 files only (this ticket + `feed_scanner.py` +
  `test_feed_scanner.py`), 430 insertions / 6 deletions, additive-only.

## Comments

- Created 2026-08-16 during 09.1 (technique cache TTL) work; based on the
  codegraph impact scan showing `scan_feed` -> `enrich_hypotheses` with no
  `enrich_predictions` reachability, and Ticket 11's populated-field
  expectation.
- Resolved 2026-08-16: Option A implemented ahead of Ticket 11 so the
  acceptance/smoke expectation ("populated when `threadlinqs_enabled=True`") is
  truthful in the live path.