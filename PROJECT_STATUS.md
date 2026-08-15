# PROJECT_STATUS.md — AdversaryGraph HERMES extension (handoff)

## Current goal
Management demo: a web page that shows, in Russian, a threat summary plus hunt
hypotheses relevant to KZ/CIS and to client sectors, with NATO Admiralty confidence
codes and per-tenant coverage / blind-spot status and copy-ready AQL, replacing manual
rule copying.

## Standing process rules
- Every session starts by reading this file, confirming progress, then continuing.
- Use Matt Pocock skills in OpenCode: /grill-with-docs before code, /to-spec,
  /to-tickets, /implement (tdd + code-review), /handoff at stage end to update this file.
- Additive-only: never rewrite existing AdversaryGraph routers/pages; append new files.
- One module per step; run tests between steps.

## Done and verified
- M1 Threadlinqs MCP client (stdio npx intelthreadlinqs-mcp, long-lived session,
  initialize handshake, reconnect) + normalizer + relevance scorer + ioc_classifier +
  circuit breaker + daily rate limiter + redis cache. Live: Purple tier, 54 tools.
- M2 rules parser (strip_yaml_values) + fields harvest + constants (INDEXED_FIELDS
  qid/logsourceid/devicetype/domainid; canonical_log_source map; LAST mandatory,
  indexed-first warning).
- M3 BB resolver (own_conditions chain, effective_fallback tag, ResolutionError /
  MissingBuildingBlock).
- M4 regex_guard done (degraded regex detection). AQL emitter + fp_injector partial.
- M6.1 coverage analyzer: statuses COVERAGE_GAP / DRL_BLIND / FIELD_PARTIAL /
  SYSMON_BLIND / COVERED; parent/child MITRE dot-boundary match; best-status
  aggregation; secondary flags; chokepoint bonus 1.25; per-tactic ratio. 14/14 tests.
- M6.2 live smoke scripts/coverage_live_smoke.py: real bundle TL-2026-1693 x 3 tenants;
  finance priority above energy; critical_infrastructure collapses into DRL_BLIND.
- Docs: ARCHITECTURE_AUDIT.md, CHANGE_PLAN.md (Locked decisions v2),
  HYPOTHESIS_ENGINE.md, AGENT_SKILLS.md.
- Frontend: Hypotheses page (frontend/src/pages/Hypotheses.tsx, route `/hypotheses`,
  sidebar order asserted by e2e smoke) — persisted scan rows: tenant/status filters
  via URL params, Admiralty code, coverage status, covering rules, chokepoints,
  expected evidence; Validate/Reject via PATCH /hypotheses/:id (only analyst can
  advance `proposed`); 3 e2e specs passing with mocked API. Frontend suite green:
  58 passed, 4 skipped; lint + tsc clean.
- M6.4 backend: Hypothesis schema (schemas/hypothesis.py), in-memory + JSON store
  (services/hypothesis_store.py; status lifecycle, updated_at stamp, M5 DB seam),
  deterministic generator (services/hypothesis_generator.py — reuses normalize→
  score→analyze→Admiralty pipeline, min_relevance gate), feed scanner
  (tasks/feed_scanner.py — provenance-shaped prog logs; offline-bundle default),
  routes GET/PATCH /api/hypotheses (module flag hypothesis_enabled default off;
  hypothesis:view list / hypothesis:validate PATCH), Hypotheses OpenAPI tag.
  Backend suite green: 915 passed, 11 skipped; ruff clean. e2e still mocks the
  hypotheses endpoints until a live scan run seeds fixtures/hypotheses.json.

## Key decisions (do not re-litigate)
- availability comes from rule.custom_fields, not a fields.yaml join (names differ).
- sysmon checked via drl_matrix key "sysmon"; DRL threshold 2.
- technique status = best across covering rules; secondary flags = union minus primary.
- NATO Admiralty (source letter A-F + credibility digit 1-6) to be applied in M6.3.
- Two-level source model: platform type catalog + per-client instances; tenant carries
  qradar_domain_id for DOMAINNAME(domainid) scoping; START/STOP for retro-hunt, LAST for
  detection.
- Rulebook fixture is a 14-rule extract of 85/346; full export still needed for a real
  coverage picture.
- PostgreSQL deferred to M5; pgvector planned for memory (M9). Attack Simulation out of
  scope.

## Environment facts
- Repo: c:\Users\b.tole\Desktop\adversarygraph-main
- venv interpreter absolute path:
  c:\Users\b.tole\Desktop\adversarygraph-main\.venv\Scripts\python.exe
  (relative .venv\... fails in PowerShell)
- backend/.env is gitignored and holds THREADLINQS_API_KEY, THREADLINQS_ENABLED and
  DB_PASS local placeholder. Never print the key.
- pytest: run with -o addopts= or --no-cov (ini has a repo-wide cov gate); conftest
  imports main, so fastapi and db_pass must be present.
- pySigma imports as "from sigma... import", never "import pysigma".
- Windows cp1252 console may render em dashes as garbage; cosmetic only.
- Fixtures: backend/fixtures/full_rules85.yaml (14 rules), fields.yaml, shared_bbs.yaml.
- rag.py f-string backslash SyntaxError was fixed by hoisting re.sub; the single
  additive-only exception, recorded in CHANGE_PLAN.

## Known issues and failed approaches
- inline python -c with nested quotes breaks in PowerShell; always use files.
- relative .venv invocation breaks; use the absolute interpreter path.
- "import pysigma" is wrong; the package is sigma.
- Settings import raised ValidationError without db_pass and _get_api_key swallowed it;
  fixed by DB_PASS in .env.

## Next steps (ordered)
1. M6.4 done and verified. GATE: run the first live feed scan ONLY after user
   review of this slice (objective: STOP for review first) — `scan_feed()` via a
   management command or the celery task on a fixture run, confirm hypotheses
   land in fixtures/hypotheses.json.
2. Point frontend /hypotheses at the real endpoints (drop the e2e mock) after a
   seed scan; re-run hypotheses e2e against the live backend shape.
3. After the demo: M5 (PostgreSQL tenants, rulebook, hypothesis rows — replace
   the in-memory store seam), full rulebook import, M7/M8 agents and skills
   registry, M9 memory and HITL.

## Open questions for the grill
- LLM booster for hypotheses remains deferred (deterministic templates are the
  default path); revisit only if demo needs richer narrative.
- shared_bbs.yaml procedure enrichment (own_conditions/full_bb_logic) was
  flagged in review and deliberately skipped — hypotheses carry RU narratives
  from the coverage pipeline instead.
