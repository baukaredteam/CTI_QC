# Spec: Hypothesis enrichment — «Обогащение гипотез» (M6.4)

Status: `ready-for-agent`

## Problem Statement

After M6.3 the analyst sees a BLUF summary and a priority-sorted list of hunt
hypotheses, but each Hypothesis carries only an Admiralty code, a coverage
status, covering rules, and copy-ready AQL. Four classes of problems remain:

1. **No offline MITRE basis.** Technique names/tactics for the hypotheses come
   only from the live enrich path; when it is unavailable there is no
   deterministic offline basis, and the fixture referenced in docs does not
   exist on disk.
2. **GPO-dependent detections are invisible.** Some key fields (e.g. `cmdline`)
   only contain data when GPO settings are configured; the analyst is not told
   that a required telemetry field needs extra configuration.
3. **Expected evidence is hardcoded.** `expected_evidence_ru` is assembled from
   a hardcoded candidate-field list instead of being derived from MITRE data
   sources × per-field availability × requires_gpo × adversary playbooks, so
   it does not reflect the actual coverage status of the tenant.
4. **No hunt-intelligence enrichment.** Hypotheses are not enriched with
   related threats, adversary playbooks, infrastructure pivots, or predicted
   next techniques from the Threadlinqs MCP, and they give no 1.25
   confidence-priority bonus for high-confidence actors.

## Solution

Extend the hypothesis pipeline additively so that every Hypothesis carries:

- **Deterministic MITRE ATT&CK v15 metadata** (name, tactic, data sources) from
  a committed YAML fixture, resolved through a four-level fallback that never
  requires the MCP to produce names.
- **A `requires_gpo` flag per detection field**, so telemetry requirements
  that depend on GPO configuration are explicit to the analyst.
- **Blind-spot marker prefixes in `expected_evidence_ru`** — one of
  `COVERAGE_GAP` («нет покрывающего правила»), `DRL_BLIND` («источник не видит
  событие»), `FIELD_PARTIAL` («частичное покрытие»), `SYSMON_BLIND`
  («Sysmon не охвачен») — derived from the coverage status, formatted
  `"{маркер} — {текст}"`.
- **A `confidence_priority_bonus`** (`float | None`): `priority × 1.25` when
  `actor_confidence == "high"`, else `None`. Display-only; never mutates the
  existing priority and never reorders the M6.1 queue.
- **MCP hunt enrichment** from `get_threat_hunting_bundle` (related threats,
  adversary playbooks, infrastructure pivots) and `predict_mitre_transitions`
  (predicted next techniques, `attack_flow` basis surfaced in the UI) — all
  with graceful pass-through when the MCP is unavailable.

Output stays deterministic and offline-first: every new capability has a
no-MCP fallback, and the whole slice is ADDITIVE-ONLY.

## Locked Decisions

Round 1 (Q1–Q6) and Round 2 (R2-Q1…R2-Q4) are locked and are **not** to be
re-litigated. Recorded verbatim:

- **Q1 → (d)** Static MITRE ATT&CK v15 fixture is the offline basis; the live
  enrich path (`technique_enrichment.enrich_technique_maps`, `get_mitre_technique`)
  is not touched.
- **Q2 → (a)** `requires_gpo` attribute lives in `fields.yaml`; the fields
  parser reads it.
- **Q3 → (a)** IOCs stay global to the threat; IOC→technique binding is
  deferred to M7 (agent Pivot, `get_ioc_blast_radius`).
- **Q4 → (b)** With isolation from M6.1 — closed by R2-Q3 (new display-only
  field; existing priority is never mutated).
- **Q5 → (a)** RU blind-spot markers for the four coverage-status classes are
  prefixed into `expected_evidence_ru`.
- **Q6 → (a)** Acceptance criterion is quality: non-empty `technique_name` /
  `tactic` for v15 techniques, no placeholder names where `name == id`; the 280
  hypothesis target is re-checked after the GATE scan.
- **R2-Q1** — The MITRE fixture is the minimal triple
  `technique_id → {name, tactic, data_sources[]}`, in YAML, at
  `backend/fixtures/mitre_attack_v15.yaml`. Provenance header: `version: 15.x`,
  `generated_at`, `source` (STIX bundle name / URL), `license: CC-BY-4.0`. A
  deterministic offline generator script produces it; the result is committed;
  the STIX bundle is **not** stored. The loader lives **inside**
  `app/services/mitre_meta.py` — no parallel module.
- **R2-Q2** — `requires_gpo` in `fields.yaml`: `cmdline=true` (cited from 8
  rules in `full_rules85.yaml` at lines 593, 689, 784, 877, 969, 1139, 1232,
  1305 plus the shared-basis block in `shared_bbs.yaml` at lines 95–105:
  «Если GPO — пустое поле»); the other 41 fields explicitly `false`. The
  `fields_harvest` parser reads it additively.
- **R2-Q3** — New field on the Hypothesis schema:
  `confidence_priority_bonus: float | None = None`. Computed in
  `generate_hypotheses` as `priority × 1.25` when `actor_confidence == "high"`,
  else `None`. The existing `priority` is **not** mutated. Display-only.
- **R2-Q4** — Blind-spot markers are prefixes on `expected_evidence_ru`,
  formatted `"{маркер} — {текст}"`:
  `COVERAGE_GAP` → «нет покрывающего правила» (the existing `GAP_MARKER_RU`,
  `management_service.py:107`), `DRL_BLIND` → «источник не видит событие»,
  `FIELD_PARTIAL` → «частичное покрытие», `SYSMON_BLIND` → «Sysmon не охвачен».
  The four terms enter CONTEXT.md.

## Implementation Decisions

- **Hard constraint HC-1** — `threadlinqs_mcp_enricher.enrich_hypotheses(hypotheses, client) -> list[Hypothesis]` is **pure**: it returns **new** objects via `model_copy` and never mutates the input list.
- **Hard constraint HC-2** — Batched: one `get_threat_hunting_bundle` call per unique `threat_id`, one `predict_mitre_transitions` call per unique `technique_id`. Cache key `tl:technique:*` with TTL 7 days. When `_breaker` is open or `threadlinqs_enabled=False`, the function is a pass-through returning the input list unchanged.
- **Hard constraint HC-3** — `mitre_meta.py` does **not** import `threadlinqs_client` / `threadlinqs_cache` and never touches the network. The resolver accepts an optional `live_lookup: Callable[[str], dict | None]` (default `None`) plus `bundle_names`; with `live_lookup=None` fallback levels 1/3/4 still work. The closure `client.get_mitre_technique` + `ThreadlinqsCache.get_technique` is passed in by `scan_feed`. Module purity and the `generate_hypotheses` seam are preserved.
- **Contract 3.1 — MITRE v15 fixture.** Minimal triple `technique_id → {name, tactic, data_sources[]}`; provenance `source=threadlinqs_mcp_export_stix`; `license: CC-BY-4.0`. Four-level fallback for technique metadata, in order: (1) bundle names from the Threadlinqs normalizer; (2) `ThreadlinqsClient.get_mitre_technique` + `ThreadlinqsCache.get_technique` (live, 7-day cache); (3) the YAML v15 fixture (offline, tests); (4) hardcoded `TTP_TACTICS` / `TECHNIQUE_NAMES`. Single entry point in `mitre_meta.py` — no parallel modules. **Generator (ticket 01) uses the existing generic `ThreadlinqsClient.call_tool("export_stix", {...})` + local parse of the result — it does NOT wait for the typed `export_stix` wrapper that ticket 06 adds for the runtime enricher.** The typed wrapper (ticket 06) and the generator (ticket 01) share the same underlying MCP tool but live in separate layers. **Guardrails F1–F4 apply (see ticket 01):** (F1) the 47-technique union (rules ∪ TL-2026-1693 bundle ∪ `TTP_TACTICS`/`TECHNIQUE_NAMES` keys) is the *minimal assertion set* — tests assert `union ⊆ fixture`, each resolving to non-empty `name`+`tactic`, `name == id` forbidden; the fixture itself is an export-derived *superset* and may be wider than 47; (F2) the generator is two layers — `fetch_stix(client)` (live export, manual commit-generation only, never invoked in tests/CI) and `build_fixture(stix_objects, provenance) -> bytes` (pure, deterministic; the determinism test feeds it the committed `tests/fixtures/stix_sample.json` + fixed provenance and asserts byte-identical output across two calls — the live export is never exercised in tests, avoiding quota/flakiness); (F3) provenance `generated_at` is date-only `YYYY-MM-DD` (never a timestamp), with stable serialization (sorted keys, fixed indent, `allow_unicode`) so "two runs = identical bytes" holds; (F4) `data_sources`: if the `export_stix` attack-pattern objects carry no detection data sources, the generator enriches each technique at manual-generation time via `get_mitre_technique(include_threats=False)` (batched, cached under `tl:technique:*`); the unit test asserts non-empty `data_sources` for the 47 union techniques — canary `T1518.001` (documented placeholder-fallback case) is a *soft* check: if absent from the generated fixture, the generator emits a WARN + a `map.md` note, **not** a ticket failure (covered by fallback level 2 live).
- **Contract 3.2 — `requires_gpo`.** `cmdline=true` per the citation in R2-Q2; the other 41 fields explicitly `false`; `fields_harvest` reads and propagates it into the field model additively. Actual file on disk: `backend/fixtures/fields.yaml` (not the documented typo `fileds.yaml`).
- **Contract 3.3 — `expected_evidence_ru`.** Built from MITRE data sources × `fields.yaml` availability × `requires_gpo` × `adversary_playbooks`; **not** a hardcoded `_CANDIDATE_FIELDS` expansion. Blind-spot markers prefixed per the coverage status (P1: `GAP_MARKER_RU` stays in `text_ru` **and** is added to `expected_evidence_ru`; the other three markers appear **only** in `expected_evidence_ru`).
- **Contract 3.4 — Candidate chokepoints.** Canonical formulation:
  `candidate_chokepoints(technique_id)` = телеметрические поля техники (шаблоны
  mitre_meta) ∩ записи `fields.yaml` с `adversary_control: LOW`. It does
  **not** depend on covering rules — it must work for COVERAGE_GAP hypotheses
  (no rules exist). Rule-derived LOW fields stay in the existing `chokepoints`
  field (`_chokepoints_for`) — untouched.
- **Contract 3.5 — MCP enrichment.** `get_threat_hunting_bundle(threat_id, simulation_limit=3, pivot_limit=25)` → `related_threats`, `adversary_playbooks` (enriches `expected_evidence_ru`), `infrastructure_pivots` (supplements IOCs, never replaces). `predict_mitre_transitions(technique_id, direction='forward', top_n=5, basis='any')` → `predicted_next_techniques` with basis `attack_flow` (surfaced in UI) vs `mitre_canonical` / `blended` (raw only). Rate limit 5000/day; batch 20 techniques in parallel; MCP timeout 5s; graceful fallback via the existing `_breaker` (3/60s) and `threadlinqs_enabled=False` → empty results, never an exception.
- **Orchestration seam.** `scan_feed` invokes `enrich_hypotheses` immediately after `generate_hypotheses` (the Threadlinqs client is already in scope there for `enrich_technique_maps`). `generate_hypotheses` itself stays pure — no MCP inside.
- **Schema changes (serialized).** Tickets 04, 08, 09 each append fields to the Hypothesis schema; they are sequenced so the schema edits do not conflict: `confidence_priority_bonus` (04) → `related_threats` / `adversary_playbooks` / `infrastructure_pivots` (08) → `predicted_next_techniques` (09).
- **Contract 3.6 — Acceptance criteria.** Non-empty `technique_name` / `tactic` for all v15 techniques in the GATE output; no placeholder names (`name == id`); markers present exactly by coverage status; full backend suite green (baseline at slice start: 948 passed, 11 skipped) plus new tests; frontend 58 plus new tests; two GATE scan scenarios — (a) `threadlinqs_enabled=True`: `related_threats` + `predicted_next_techniques` populated, cache `tl:technique:*` hit on the second run; (b) `threadlinqs_enabled=False`: same hypotheses, MCP fields empty, no exception.

## Testing Decisions

- **Two seams.** (1) `generate_hypotheses` — the pure, highest existing seam;
  tested with synthetic input, never with MCP. (2) `threadlinqs_mcp_enricher.enrich_hypotheses` — the one new seam; tested with a `FakeThreadlinqsClient` (unit) and with the real client in T7 (integration, MCP on/off).
- **Orchestration** in `scan_feed` right after `generate_hypotheses`; the generate→enrich chain is covered by the T7 integration scenarios, not by unit tests.
- **Priority:** unit (both seams) → integration T7 (MCP on/off) → e2e `hypotheses.spec` after the GATE scan.
- **What makes a good test:** assert only external observable behavior — marker presence per coverage status, `confidence_priority_bonus` values, pass-through behavior, cache-hit vs MCP-call counts, non-mutation of the input list. Never function-internal state.
- **Modules tested:** `mitre_meta` (fallback order, determinism), `fields_harvest` (requires_gpo propagation), `hypothesis_generator` (markers, bonus, chokepoints), `threadlinqs_client` (4 new methods), `threadlinqs_normalizer` (3 extraction blocks), `threadlinqs_mcp_enricher` (batching, pass-through).
- **Prior art:** `tests/unit/test_m6_coverage.py` (pure functions over fixture input, no DB); `tests/unit/test_hypothesis_generator.py` for the generator seam; `tests/unit/test_threadlinqs_client.py` / `test_threadlinqs_normalizer.py` for the client/normalizer seams.

## Out of Scope

- IOC→technique binding and the Pivot agent (`get_ioc_blast_radius`) — M7.
- DB-backed tenants / PostgreSQL persistence of hypotheses — M5.
- Full rulebook import beyond the 85-rule basis.
- e2e-vs-backend run before the GATE scan (Redis is down → cache off; `DB_PASS` not provided → e2e against the backend is blocked).
- Any rewrite of M6.1 coverage/admiralty/priority logic or of the working
  `threadlinqs_client.py` / `threadlinqs_cache.py` / `threadlinqs_normalizer.py`
  behavior — additions only.

## Further Notes

- **ADDITIVE-ONLY** — the slice adds files and appends lines; nothing existing is rewritten.
- **Rollback** — delete the new files and revert the added lines; no migration is introduced (schema fields are optional with defaults).
- Deterministic path (fixture + hardcoded fallback, no MCP) must produce identical bytes offline and live — unit tests pin this down.
- Russian-facing strings come from the CONTEXT.md glossary vocabulary exactly: Coverage status classes (`COVERAGE_GAP`, `DRL_BLIND`, `FIELD_PARTIAL`, `SYSMON_BLIND`), Chokepoint, Admiralty code, Hypothesis, blind spot, copy-ready AQL. No synonyms.
- This spec lands as `Status: ready-for-agent`; no further triage required.
