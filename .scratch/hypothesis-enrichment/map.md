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

- Exact tool names for `export_stix`, `get_attack_flow`, `get_threat_hunting_bundle`, `predict_mitre_transitions` are plan-level; confirm against the real Threadlinqs tool list (54 tools, Purple tier) during ticket 06 / smoke in ticket 11. `get_mitre_technique` is confirmed by the existing enrich path.
- The 280-hypothesis acceptance target is re-checked after the GATE scan (ticket 11).
