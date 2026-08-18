# Map: Hypothesis enrichment (M6.4)

Effort map — notes, decisions-so-far, fog. Children live in `issues/`.

## Notes

M6.4 extends the M6.3 hypothesis pipeline additively: deterministic MITRE v15
metadata, `requires_gpo` awareness, blind-spot markers in
`expected_evidence_ru`, a display-only confidence-priority bonus, and MCP hunt
enrichment (bundle + predicted transitions). Verification snapshot confirmed
the dependency tree is identical to the earlier snapshot: `generate_hypotheses`
(`hypothesis_generator.py:214`), `scan_feed` (`feed_scanner.py:113`),
`technique_meta` (`mitre_meta.py:156`), `candidate_fields` (`:181`),
`gap_expected_evidence_ru` (`:190`), `Hypothesis` (`schemas/hypothesis.py:35`),
`list_hypotheses` (`hypothesis_store.py:58`). `PROJECT_STATUS.md` unchanged.

## Decisions-so-far

Locked R2 answers (Q1–Q6 recorded verbatim in `spec.md`):

- **R2-Q1** — MITRE v15 fixture = minimal triple `technique_id → {name, tactic, data_sources[]}`, YAML at `backend/fixtures/mitre_attack_v15.yaml`, provenance header (`version: 15.x`, `generated_at`, `source=threadlinqs_mcp_export_stix`, `license: CC-BY-4.0`), deterministic committed generator, STIX bundle not stored, loader inside `app/services/mitre_meta.py`.
- **R2-Q2** — `requires_gpo`: `cmdline=true` (8 rules in `full_rules85.yaml:593,689,784,877,969,1139,1232,1305` + `shared_bbs.yaml:95-105`), other 41 fields explicitly `false`; `fields_harvest` reads additively. Actual fixture: `backend/fixtures/fields.yaml`.
- **R2-Q3** — `confidence_priority_bonus: float | None`, `priority × 1.25` at `actor_confidence == "high"` else `None`; priority never mutated; display-only.
- **R2-Q4** — Marker prefixes `"{маркер} — {текст}"`: `COVERAGE_GAP`→«нет покрывающего правила», `DRL_BLIND`→«источник не видит событие», `FIELD_PARTIAL`→«частичное покрытие», `SYSMON_BLIND»→«Sysmon не охвачен».

Architectural amendments:

- **P1** — `GAP_MARKER_RU` stays in `text_ru` and is also added to `expected_evidence_ru`; the other three markers appear only in `expected_evidence_ru`.
- **P2** — bonus is display-only: never mutates the M6.1 `rec.priority`, never reorders `analyze_coverage`, UI highlight only.
- **P3** — single meta-facts entry point in `mitre_meta.py`, 4-level fallback: bundle names → MCP live + cache → YAML v15 → hardcoded `TTP_TACTICS`/`TECHNIQUE_NAMES`.
- **P4** — generator script (`backend/scripts/generate_mitre_v15_fixture.py`, next to `smoke_threadlinqs.py`, same `sys.path` convention) uses the existing generic `ThreadlinqsClient.call_tool("export_stix", {...})` + local parse as canonical STIX source; result committed, source not stored. **Does NOT depend on the typed `export_stix` wrapper from ticket 06** — typed wrapper is for the runtime enricher; generator stays on the raw call.
- **P5** — `get_threat_hunting_bundle(threat_id, simulation_limit=3, pivot_limit=25)`: `similar_threats→related_threats`, `simulations→adversary_playbooks`, `infrastructure_pivots→infrastructure_pivots`; graceful fallback via existing `_breaker` (3/60s); `threadlinqs_enabled=False` → empty lists, no exception.
- **P6** — `predict_mitre_transitions`: `predicted_next_techniques` with basis `attack_flow` (UI) / `mitre_canonical` / `blended` (raw only); DailyRateLimiter 5000/day; cache `tl:technique:*` TTL 7 days; batch 20 in parallel; MCP timeout 5s; fallback empty list.

Hard constraints (approved with the seams):

- **HC-1** — `enrich_hypotheses(hypotheses, client) -> list[Hypothesis]` is pure: returns new objects via `model_copy`, never mutates the input list.
- **HC-2** — batched: one `get_threat_hunting_bundle` per unique `threat_id`, one `predict_mitre_transitions` per unique `technique_id`; cache `tl:technique:*` TTL 7 days; `_breaker.open` / `threadlinqs_enabled=False` → pass-through of the input list unchanged.
- **HC-3** (delta B) — `mitre_meta.py` does not import `threadlinqs_client` / `threadlinqs_cache` and never touches the network. The resolver accepts an optional `live_lookup: Callable[[str], dict | None]` (default `None`) plus `bundle_names`; with `None` the fallback levels 1/3/4 work. The closure `client.get_mitre_technique` + `ThreadlinqsCache.get_technique` is passed by `scan_feed`. Module purity and the `generate_hypotheses` seam are preserved.
 - **Guardrails F1–F4** (ticket 01, see spec.md 3.1):
   - **F1** — the 47-technique union (full_rules85.yaml ∪ TL-2026-1693 `_DEFAULT_TTPS` ∪ `TTP_TACTICS`/`TECHNIQUE_NAMES` keys) is the *minimal assertion set*: tests assert `union ⊆ fixture`, each resolves to non-empty `name`+`tactic`, `name == id` forbidden. Fixture is an export-derived *superset* (may be wider than 47).
   - **F2** — generator = two layers: `fetch_stix(client)` (live export, manual commit-generation only, never invoked in tests/CI) and `build_fixture(stix_objects, provenance) -> bytes` (pure, deterministic; determinism test feeds it the committed `tests/fixtures/stix_sample.json` + fixed provenance and asserts byte-identical output — live export never exercised in tests, avoiding quota/flakiness).
   - **F3** — provenance `generated_at` is date-only `YYYY-MM-DD` (never a timestamp); stable serialization (sorted keys, fixed indent, `allow_unicode`) so "two runs = identical bytes" holds.
   - **F4** — `data_sources`: if `export_stix` attack-pattern objects carry no detection data sources, the generator enriches each technique at manual-generation time via `get_mitre_technique(include_threats=False)` (batched, cached under `tl:technique:*`); unit test asserts non-empty `data_sources` for the 47 union techniques. Canary `T1518.001` (documented placeholder-fallback case) is a *soft* check: if absent from the generated fixture, generator emits a WARN + a `map.md` note — **not** a ticket failure (covered by fallback level 2 live).

Approved seams:

1. **`generate_hypotheses`** — the pure, highest existing seam; synthetic input, never MCP.
2. **`threadlinqs_mcp_enricher.enrich_hypotheses`** — the one new seam; `FakeThreadlinqsClient` for unit tests, real client in T7 (MCP on/off).
3. Orchestration in `scan_feed` immediately after `generate_hypotheses` (client already in scope for `enrich_technique_maps`).

**Edge rationale 04→08→09:** tickets 04, 08, 09 each append fields to the
Hypothesis schema in `app/schemas/hypothesis.py`. The schema edits are
serialized (04 bonus → 08 enrichment trio → 09 predictions) so the appends
cannot conflict.

## Fog

- Exact tool names for `export_stix`, `get_attack_flow`, `get_threat_hunting_bundle`, `predict_mitre_transitions` are plan-level; confirm against the real Threadlinqs tool list (54 tools, Purple tier) during ticket 06 / smoke in ticket 11. `get_mitre_technique` is confirmed by the existing enrich path. **Ticket 01 confirmed `export_stix` is ABSENT** from the v7.1.0 tool list (54 tools enumerated, no `export_stix`) → generator gains a `--bundle PATH` mode reading the canonical MITRE ATT&CK v15.1 `enterprise-attack.json` (same canonical STIX source P4 specifies); `fetch_stix(client)`/`--write` remain for when the tool lands.
- The 280-hypothesis acceptance target is re-checked after the GATE scan (ticket 11).

## Ticket 01 — resolved (see `issues/01-mitre-v15-fixture.md`)

- Fixture `backend/fixtures/mitre_attack_v15.yaml` committed: 780 techniques,
  provenance `{version: 15.1, generated_at: 2026-08-15, source:
  mitre_attack_stix_15.1, license: CC-BY-4.0}`. Devation: `source` reads the
  canonical bundle name (not `threadlinqs_mcp_export_stix`) because the live
  MCP v7.1.0 has no `export_stix` tool — honest provenance over ticket text.
- Canary `T1518.001` present as `Security Software Discovery` (non-placeholder,
  discovery) — no WARN needed.
- Evidence: 15/15 ticket tests + 63/63 adjacent M6 suites pass (coverage-fail
  only because subset runs in isolation, total-suite coverage unaffected).

## Ticket 02 — resolved (see `issues/02-requires-gpo.md`)

- `backend/fixtures/fields.yaml`: all **54 entries** on disk carry an explicit
  `requires_gpo`; `cmdline: true`, the other 53 explicitly `false`. The
  ticket's "42 fields / other 41" was the stale `metadata.total_fields: 42`
  figure — the fixture drifted to 54 entries (49 unique names;
  `proc_file_path` ×3, `event_description` ×2, `task_name` ×2,
  `proc_usr_sid` ×2). Every entry got the flag; `metadata.total_fields` left
  untouched (ADDITIVE-ONLY).
- Propagation: `CustomField.requires_gpo: bool = False` (schema),
  `HarvestedField.requires_gpo: bool = False` + readers OR-set it from
  `cf.requires_gpo`, `merge_harvests` OR-combines. Legacy input without the
  key defaults to `false` (schema + harvest) — no error.
- Evidence: 9/9 ticket tests green; full backend regression **977 passed,
  11 skipped**, coverage 69.25% (gate `--cov-fail-under=60` passes on the
  full run; lone-file runs cannot reach it — same note as ticket 01).

## Ticket 03 — resolved (see `issues/03-blind-spot-markers.md`)

- Marker constants live in `management_service.py` (R2-Q4 exact text);
  `BLIND_MARKER_RU["COVERAGE_GAP"]` reuses `GAP_MARKER_RU` — no duplicate.
- `_apply_blind_marker_ru(status, text)` in `hypothesis_generator.py`,
  applied only at `expected_evidence_ru` assembly: idempotent, exact-key
  statuses only (`COVERED`/unknown/`None` pass through unmarked); `text_ru`
  untouched — P1 stream separation pinned by tests.
- Expected evidence now derived from v15 `data_sources` × `fields.yaml`
  availability × `requires_gpo` × `adversary_playbooks` seam (ticket 08);
  the M6.4 generator path no longer uses `_CANDIDATE_FIELDS`.
- Evidence: 15 new tests (targeted 38/38 green with `addopts=""`); full
  backend regression **992 passed, 11 skipped**, coverage 69.30%; ruff clean
  on all changed files.

## Ticket 04 — resolved (see `issues/04-confidence-priority-bonus.md`)

- `Hypothesis.confidence_priority_bonus: float | None = None` appended as the
  last schema field (first of the 04→08→09 serialized appends); no migration,
  absent JSON key reads as `None` (backward-compatible round-trip pinned).
- `generate_hypotheses` computes `priority × 1.25` only when the normalized
  `actor_confidence` is canonical high — existing predicate
  `str(conf).lower() in {"high", "высокая"}` reused; no new synonyms or
  taxonomy. `medium`/`low`/empty/`unknown`/`community` → `None`.
- Nuance encoded in tests: `_extract_attribution`'s existing `.strip()` is
  part of canonical normalization, so raw `"HIGH "` qualifies; no new
  normalization introduced.
- Display-only (P2): `priority` never mutated, ids/queue order unchanged,
  bonus excluded from scoring, sorting, validation/rejection and persistence
  decisions; 21 new tests (red phase confirmed at assertion level, not env).
- Evidence: targeted 51/51 green (`addopts=""`); full backend regression
  **1013 passed, 11 skipped**, coverage 69.30% (gate `--cov-fail-under=60`
  passes on the full run); ruff clean on changed files.

## Ticket 05 — resolved (see `issues/05-chokepoints-low.md`)

- `candidate_chokepoints` in the generator = telemetry templates ∩
  `fields.yaml` entries with exact `adversary_control == "LOW"` (canonical
  strip+upper normalization; every duplicate entry must declare LOW —
  contradictory duplicates are excluded). Works for COVERAGE_GAP rows with
  zero covering rules (pinned via technique T1613 → fallback template
  `dns_rname`).
- New pure parse seam `mitre_meta.parse_fields_catalog` (duplicates merge:
  availabilities union, `requires_gpo` OR, controls union per name, first
  non-empty note wins); `fields_catalog()` keeps its signature/degradation.
- Semantics note: the old candidates came from the hardcoded
  `_CANDIDATE_FIELDS` list (HIGH fields included); `mitre_meta.candidate_fields`
  and the M6.3 management summary keep their existing behavior — only the
  hypothesis-generator path swapped, per ticket 05 boundary. Rule-derived
  `chokepoints` (`_chokepoints_for`) untouched; no new Hypothesis schema
  fields; catalog notes ride the existing `note_ru`.
- Evidence: targeted 76/76 green (`addopts=""`, incl. `test_m6_meta.py`);
  full backend regression **1030 passed, 11 skipped**, coverage 69.33%
  (gate `--cov-fail-under=60` passes on the full run); ruff clean on
  changed files.

## Post-Ticket 05 — hardening hotfix: canonical `requires_gpo` coercion

- **Bug**: `parse_fields_catalog` used `bool(cf.get("requires_gpo", False))`;
  for raw string input `bool("false") is True`, so untrusted QRadar YAML
  values flipped `requires_gpo` (and, merged by OR, its duplicates) to the
  wrong truthiness; unknown strings were always truthy.
- **Fix**: one pure, deterministic helper `mitre_meta._coerce_bool` in the
  canonical parser layer with an explicit token policy — native bool
  preserved; string (strip, case-insensitive) `{true, yes, 1, on}` → True,
  `{false, no, 0, off}` or empty/whitespace → False; `None` or any unknown
  raw value/type → default False, never truthy (mirrors the module's
  silent-degradation style). Only the direct `bool(...)` coercion in
  `parse_fields_catalog` was replaced; the duplicate OR-merge and the
  `fields_catalog` public shape are unchanged.
- Scope guard: `fields_harvest` (ticket 02, Pydantic-typed path),
  `_chokepoints_for`, `candidate_chokepoints` semantics, priority,
  Admiralty, coverage, markers, confidence bonus, schemas, API and MCP are
  all untouched — the ticket 03-05 invariant tests stay green.
- Evidence: 12 red → green (token policy + duplicate OR-merge + LOW
  invariance + determinism); targeted 119/119 (`addopts=""`); full backend
  regression **1064 passed, 11 skipped**, coverage 69.34% (gate
  `--cov-fail-under=60` passes); ruff clean on changed files.

## Ticket 06 — partially-implemented (see `issues/06-client-mcp-methods.md`)

- Three methods accepted independently, each verified against the v7.1.0 tool
  registry (`intelthreadlinqs-mcp@7.1.0`, `dist/index.js`): `get_threat_hunting_bundle`
  (schema `{threat_id}` only — `simulation_limit`/`pivot_limit` stay
  signature-level placeholders, NOT sent), `predict_mitre_transitions`
  (`{technique_id, direction, top_n, basis}`, 1:1 with the public signature),
  `get_attack_flow` (`{threat_id}`, 1:1). Each goes through the existing
  `_execute` degradation set (disabled flag / breaker / rate limit / timeout /
  session loss / malformed payload → `{}`, never an exception).
- Evidence: 26/26 targeted tests green (cross-checked live: 26 passed in
  17.11s), full backend regression green at the commit
  (`1064` before + ticket-06 additions).

## Decision record (2026-08-16): `export_stix` deferred — Ticket 07 is unblocked

- **DECISION:** Ticket 07 **can start without `export_stix`**. Ticket 01
  already commits the offline MITRE v15 fixture
  (`backend/fixtures/mitre_attack_v15.yaml`, 780 techniques, provenance
  `source: mitre_attack_stix_15.1`) and reads it deterministically — the
  fixture generator's `fetch_stix`/`--bundle PATH` mode already covers the
  STIX source need without the typed wrapper.
- **`export_stix` stays a separate runtime/STIX follow-up**, owned by
  `issues/06B-export-stix.md` (status NEEDS_DECISION, blocked). Unblock
  conditions: (1) the tool appears in the real MCP tool list, or (2) the owner
  provides an official schema contract. After either, required tests:
  success-shape, fallback (5 degradation paths → `{}`), and secret-leak
  (API key never re-emitted). No stub / fake result / roadmap-based wrapper /
  invented schema — the standing «не выдумывай контракт» gate applies.
- **Boundary:** Ticket 06 stays `partially-implemented`; the three verified
  methods are accepted independently and `export_stix` is explicitly NOT part
  of that acceptance. Production code, tests, schemas and MCP config were not
  touched by this bookkeeping step.

## Ticket 07 — resolved (see `issues/07-normalizer-extractions.md`)

- Three pure extraction blocks appended to `threadlinqs_normalizer.py`:
  `_extract_simulations` → `adversary_playbooks`, `_extract_pivots` →
  `infrastructure_pivots`, `_extract_similar_threats` → `related_threats`,
  over a shared `_extract_text_items` helper (str trim, dict text-key
  priority, `dict.fromkeys` order-preserving dedupe). Pivot dicts keep only
  scalar values (nested dicts/lists/None dropped, empties excluded) and are
  deduped by canonical sorted-key JSON — first occurrence wins.
- Contract: missing/None/malformed/wrong-type input → `[]`, never an
  exception; extracted text is data, never evaluated or executed (pinned by a
  test feeding command-injection strings and an `__import__('os')` payload as
  plain text). Prefix-key priorities: simulations
  `("playbook", "name", "title", "value")`, threats
  `("name", "title", "value", "id")` — unknown-key dicts skipped.
- Wiring: `normalize_bundle` reads the three envelope keys with the existing
  `data`-fallback convention and passes them into the `NormalizedThreat(...)`
  constructor keywords; three `default_factory=list` fields appended to the
  dataclass. The only constructor call site uses keyword args — byte-compatible
  append, no positional construction anywhere in `app/` or `tests/`.
- ADDITIVE-ONLY verified by diff: new `import json`, 3 fields, 4 functions,
  wiring only; `_extract_indicators` / `_extract_techniques` untouched. Pivots
  supplement IOCs, never replace them (a domain as both IOC and pivot stays in
  both — pinned test).
- Evidence: red phase 21 failed / 2 passed (assertion-level, missing symbols);
  targeted **23/23 green**, existing Threadlinqs suites **72/72 green**; full
  backend regression **1113 passed, 11 skipped**, coverage 69.48% (gate
  `--cov-fail-under=60` passes on the full run); `ruff check` clean on the
  changed file (`ruff format` drift pre-existing — HEAD fails format-check
  identically; CI gates on `ruff check .`).

## Ticket 08 — resolved (see `issues/08-mcp-enricher.md`)

- New seam `app/services/threadlinqs_mcp_enricher.py`: `enrich_hypotheses(
  hypotheses, client) -> list[Hypothesis]` — pure (`model_copy` new objects,
  input list never mutated), batched (one `get_threat_hunting_bundle(
  threat_id, simulation_limit=3, pivot_limit=25)` per unique threat_id,
  first-seen order, map-back by threat_id), pass-through on
  `_INTEGRATION_ERRORS` = `(ThreadlinqsClientError, CircuitOpenError,
  RateLimitExceeded, asyncio.TimeoutError, McpError)` and on bundles lacking
  any of the three enrichment keys at depth-1/`data` (degraded `{}` included)
  — same objects, never an exception.
- Extraction reuses the ticket 07 `normalize_bundle` seam (single
  envelope-reading place); `adversary_playbooks` also enriches
  `expected_evidence_ru` with one idempotent append
  (`"{text} adversary playbooks: A, B."`, skipped when already present).
- Schema: three `default_factory=list` fields (related_threats,
  adversary_playbooks, infrastructure_pivots) appended after
  confidence_priority_bonus — Ticket 08 is the second of the 04→08→09
  serialized appends; no migration, absent keys read as `[]`.
- Orchestration: `scan_feed` imports the seam inside the existing `if live:`
  lazy-import block and calls it immediately after `generate_hypotheses` when
  `client is not None`; offline scans (client None) skip it and stay
  byte-identical (pinned by the untouched offline integration tests).
- Evidence: red 25/25 (`NotImplementedError`); targeted **25/25 green** +
  new live-path scanner integration test (fake live client, one batched call
  `("TL-2026-1693", 3, 25)`, all three fields + evidence phrase on persisted
  rows) — scanner suite 4/4; full backend regression **1139 passed,
  11 skipped** in 95.65s; `ruff check` clean on changed files (lone ASYNC230
  in `scripts/coverage_live_smoke.py` is pre-existing, file untouched).

## Ticket 11 — smoke + guardrail done; GATE scan blocked on user review (see `issues/11-acceptance-and-smoke.md`)

- **API-key leak fixed**: the smoke script printed `api_key[:6]` in its banner;
  now prints the inert marker `configured=true` and never the key or a prefix.
- **Four-tool smoke section** live-validated against the real v7.1.0 server:
  `get_threat_hunting_bundle` → PASS (registered; real envelope), `export_stix`
  → NOT_AVAILABLE (absent from the 54-tool registry — consistent with 06B
  NEEDS_DECISION), `get_attack_flow` and `predict_mitre_transitions` →
  EMPTY_FALLBACK (absent from registry) — honest statuses, never faked;
  exit 0. `_process_bundle` now uses the ticket-06-verified
  `{threat_id}`-schema call.
- **Guardrail acceptance test** `backend/tests/unit/test_smoke_guardrail.py`
  (5 tests, `test_mitre_meta.py` source-guard convention): AST scan — no
  `print()` may reference `api_key` in any form; no key-prefix slice anywhere;
  configured path prints exactly `configured=true`; no-key behavior — skip
  notice, exit 0, no connect. 5/5 green; ruff clean.
- Evidence: full backend regression **1181 passed, 11 skipped**, coverage
  69.68% (gate `--cov-fail-under=60` passes); smoke exit 0 live.
- **Status `ready-for-human`**: the two live GATE scan runs
  (`threadlinqs_enabled=True` / `False`), the contract 3.6 quality gate, and
  e2e `hypotheses.spec` remain blocked per PROJECT_STATUS STOP-for-review gate
  ("run the first live feed scan ONLY after user review of this slice") and
  the missing `DB_PASS` for e2e — recorded as documented limitations, not
  failures.
