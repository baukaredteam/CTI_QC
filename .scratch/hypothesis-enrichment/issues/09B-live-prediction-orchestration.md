# 09B — Live prediction orchestration (decision record)

**Type:** decision
**Status:** NEEDS_DECISION
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

## Comments

- Created 2026-08-16 during 09.1 (technique cache TTL) work; based on the
  codegraph impact scan showing `scan_feed` -> `enrich_hypotheses` with no
  `enrich_predictions` reachability, and Ticket 11's populated-field
  expectation.