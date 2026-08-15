# Spec: Management — «Сводка и гипотезы» (M6.3)

Status: `ready-for-agent`

## Problem Statement

Analysts today cover KZ/CIS + client-sector threats by manually copying rules and reading a fragmented hit-list of per-technique coverage. There is no single screen that answers: *what threat is the client exposed to, how well are we covered, and which hypotheses should we hunt next*. Admiralty-source-evaluations, coverage gaps, and copy-ready AQL have to be assembled by hand from several screens (Analyzer, Threat Radar, rulebook).

## Solution

A `/management` page that renders, for a chosen threat and tenant, a Russian-language BLUF summary plus a priority-sorted list of hunt hypotheses. Each hypothesis carries:

- a NATO Admiralty code (`{letter, digit, rationale_ru}`) decided deterministically — never by the LLM;
- per-tecnique coverage status + covered-by rule(s) across the selected tenant;
- a covering-rule verdict (with a covering rule where one exists, explicit «нет покрывающего правила» otherwise);
- a `copy_ready_aql` bundle with the emitted copy-ready AQL, its `warnings` and sufficiency.

Output is deterministic and offline-first: the LLM is an optional quality booster for the summary narrative only. An analyst can hunt immediately from the copy-ready AQL, and — when no covering rule exists — the hypothesis carries the gap marker so the analyst knows they must author a new rule.

## User Stories

1. As a security analyst, I want to open a `/management` view and immediately read a Russian BLUF («Сводка») of the selected threat, so that I get the operational bottom line without reading the full report.
2. As an analyst, I want the threat's hypothesized techniques ordered by priority, so that I can hunt the most probable adversary behavior first.
3. As an analyst, I want each hypothesis to carry a NATO Admiralty code (letter + digit) with a Russian rationale, so I can communicate confidence to leadership using a standard evaluation.
4. As an analyst, I want the Admiralty letter to be derived deterministically from source structure, so the code is reproducible and never contradicted by an LLM.
5. As an analyst, I want the coverage status of each hypothesis computed per-tenant, so I know exactly which of our signatures already detect the behavior.
6. As an analyst, I want the rules that cover each behavior listed explicitly, so I can verify or adjust signature coverage rather than trust a score.
7. As an analyst, I want to be told the covering rule for a covered behavior, so I can copy the exact detection instead of re-authoring it.
8. As an analyst, I want a clearly-marked gap — «нет покрывающего правила» — when no rule covers a behavior, so I never mistake a gap for coverage.
9. As an analyst, I want a copy-ready AQL for each hypothesis, so I can paste it into the threat-intelligence tool with zero editing.
10. As an analyst, I want the copy-ready AQL to come with an explicit copy_ready flag, so I know at a glance whether the query is safe to paste.
11. As an analyst, I want emitter warnings surfaced (covering rules where I need them) so that I understand why a query is or isn't copy_ready.
12. As an analyst, I want overlap/chokepoint and secondary blind-flags on hypotheses, so I can prioritize chokepoints and understand secondary coverage signals.
13. As an analyst, I want to switch between tenants (finance/energy/critical_infrastructure) inline, so I can evaluate coverage for each client sector without leaving the page.
14. As an analyst, I want to change the threat I'm reviewing via a query param, so the view generalizes beyond the default threat.
15. As a development operator, I want the management module gated behind a feature flag (`management_enabled`) and RBAC (`management:view`), so the slice stays safe to ship incrementally.
16. As a tenant admin, I want tenant context carried through service and route seams, so coverage is always tenant-correct.
17. As a developer, I want period coverage statuses (CURRENT/FADING/STALE) driven by the smoke pipeline engine, so I reuse the existing coverage machinery instead of inventing new ones.

## Implementation Decisions

- **Additive-only**: no existing router, service, page or schema file is rewritten. Clean new modules: mini AQL emitter, management services, a management route module, a management frontend page, and the tenant seam.
- **Route**: `GET /api/management/summary?threat_id=&tenant_id=` returning the ManagementSummary. Registered with `_module_required("management")` — adds a `management` module key with `management_enabled` defaulting to `false` (mirrors the `require_module`/module-gating in `main.py`).
- **RBAC**: `management:view` permission + `<RoleGate module="management">` in the frontend route. Active-tenant view served at `/management` with `?tenant=` switch.
- **`management_service`**: the deterministic orchestrator. It reuses the existing smoke pipeline (fetch → normalize → score → analyze) and the `threadlinqs_cache`. Given `threat_id` (default `TL-2026-1693`) and `tenant_id`, it produces the summary + hypotheses. No DB rows are introduced.
- **Tenants are inline**: `tenants_provider.py` exposes inline profiles (finance/energy/critical_infrastructure) with an `active_tenant_id` setting — M5 swaps these for DB rows later, keeping the service signature unchanged.
- **Admiralty is deterministic** in `admiralty.py`: the letter comes only from source structure (B/C/D from struct/scattered/suspected classes); the digit 2–5 only from corroboration. The LLM never assigns any part. Output `{letter, digit, rationale_ru}`.
- **Hypothesis seeding**: hypotheses are seeded from the priority-sorted top-N coverage report `blind_spots`. The LLM writes narrative prose only, fed strictly `TechniqueCoverage` facts. A hypothesis whose behavior has no covering rule carries the explicit `COVERAGE_GAP` marker → «нет покрывающего правила».
- **Mini M4 emitter** (`aql_emitter.py`): `from_resolved_detection → emit`. LAST-window anchor, logsource filter, indexed-first field ordering from `INDEXED_FIELDS`, a sufficiency check, `regex_guard`, and `copy_ready` (bool) + `warnings` output. `sigma-ast` adapter and `fp_injector` are explicitly OUT for the demo (ADR-0001).
- **Copy-ready bundle**: per-hypothesis `copy_ready_aql{aql, copy_ready, warnings, sufficiency}`.
- **Per-hypothesis flags**: `secondary_blind_flags` and `is_chokepoint`.
- **Fixture naming note**: the fixture bundle lives on disk at `backend/fixtures/fields.yaml`. The per-log-source field availability for the emitter is joined from the rule's `custom_fields`, not from a `fields.yaml` join.

## Testing Decisions

- **Test the service, not the HTTP route.** The seam is `management_service.summary(threat_id, tenant_id)` (plus the pure emitter/admiralty functions). Only external observable behavior is asserted: Russian summary presence, hypothesis ordering, Admiralty codes, coverage statuses, covering rules, `copy_ready_aql` shape, warnings, and the `COVERAGE_GAP` marker.
- **Modules tested**: `aql_emitter`, `admiralty`, `management_service` (orchestration), and the emitter/admiralty pure functions individually. Route layer is exercised via a thin integration check to prove wiring, matching how sibling routes are covered.
- **Prior art**: `tests/unit/test_m6_coverage.py` is the pattern — no DB; pure functions over fixture input. Also `tests/unit/test_analyze_input_limits.py` for route-level wiring.
- **Test hygiene**: assert external behavior only — never function-internal state; no LLM calls in tests; deterministic template fallback path is the thing asserted (LLM is out of the critical path).

## Out of Scope

- `sigma-ast` adapter and `fp_injector` (ADR-0001 — OUT for the demo; emitter runs on resolved detection).
- Any LLM participation in Admiralty codes (ADR-0002).
- DB-backed tenants (M5) — inline provider now, swap later.
- Running an actual AQL/runk search engine to validate queries (no backend target tool in-slice).
- Any redesign or rewrite of the existing coverage pipeline / report schemas — they are reused as-is.
- Frontend test-coverage on the new page (matches the analyzer precedent with no covering tests).

## Further Notes

- The deterministic (template + no LLM) path must produce identical bytes in an offline/testenv as it does live — that is a hard requirement, so unit tests pin it down.
- LLM quality booster reached via the existing `get_adapter(settings.management_llm_provider)` — additive; when disabled, the deterministic template stands.
- Everything Russian-facing: BLUF «Сводка», Admiralty rationale, «нет покрывающего правила», per-coverage-hypothesis text. Use the CONTEXT.md glossary vocabulary (tags, technique statuses, terms) exactly, never synonyms.
- Reuses `threadlinqs_cache` — no duplicate pipeline/fetch logic in the new slice.
- This spec lands as `Status: ready-for-agent`; no further triage required.