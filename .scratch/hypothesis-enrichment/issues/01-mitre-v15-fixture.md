# 01 — MITRE ATT&CK v15 offline fixture

**Type:** task
**Status:** resolved
**Blocked by:** None — can start immediately

**What to build:** A deterministic offline basis for technique metadata so a
Hypothesis always carries a non-placeholder name and tactic even when the
Threadlinqs MCP is unreachable. Commits the minimal triple
`technique_id → {name, tactic, data_sources[]}` as YAML with a provenance
header, plus a deterministic generator script and the four-level fallback
resolver inside `mitre_meta.py` (bundle names → MCP live + cache → YAML v15 →
hardcoded).

**Acceptance criteria:**

- [ ] `backend/fixtures/mitre_attack_v15.yaml` exists with the minimal triple
      `technique_id → {name, tactic, data_sources[]}` and a provenance header
      (`version: 15.x`, `generated_at`, `source: threadlinqs_mcp_export_stix`,
      `license: CC-BY-4.0`); no placeholder names where `name == id`.
- [ ] `backend/scripts/generate_mitre_v15_fixture.py` deterministically
      produces the fixture from the existing generic
      `ThreadlinqsClient.call_tool("export_stix", {...})` + local parse of
      the result (canonical STIX source, P4). **It does NOT wait for the
      typed `export_stix` wrapper that ticket 06 adds for the runtime
      enricher** — the typed wrapper (ticket 06) and the generator (ticket
      01) share the same underlying MCP tool but live in separate layers.
      Two runs produce identical bytes; the STIX bundle itself is not
      committed. Script sits in `backend/scripts/` next to
      `smoke_threadlinqs.py`, same `sys.path` convention (top-level
      `scripts/` = infra utilities, no `app` imports in the script header).
- [ ] The loader lives inside `app/services/mitre_meta.py` (single entry
      point, P3); the resolver returns metadata through the four-level
      fallback: bundle names → `get_mitre_technique` + `ThreadlinqsCache.get_technique`
      (live, 7-day cache) → YAML v15 → hardcoded `TTP_TACTICS`/`TECHNIQUE_NAMES`.
- [ ] HC-3: `mitre_meta.py` imports no `threadlinqs_client` / `threadlinqs_cache`
      and makes no network calls; the resolver accepts an optional
      `live_lookup: Callable[[str], dict | None]` (default `None`) plus
      `bundle_names`. With `live_lookup=None` the fallback levels 1/3/4 work.
- [ ] With the MCP unavailable (`threadlinqs_enabled=False`), the resolver
      still returns non-empty name/tactic for v15 techniques — never a
      placeholder and never an exception.
- [ ] Unit tests `tests/unit/test_mitre_meta.py` cover determinism of the
      generator and each fallback level without MCP: `live_lookup=None`
      exercises levels 1/3/4; a fake callable exercises level 2.
 - [ ] **Guardrails F1–F4** (see spec.md 3.1):
       - **F1** — the 47-technique union (full_rules85.yaml ∪ TL-2026-1693
         `_DEFAULT_TTPS` ∪ `TTP_TACTICS`/`TECHNIQUE_NAMES` keys) is the *minimal
         assertion set*: tests assert `union ⊆ fixture`, each resolves to
         non-empty `name`+`tactic`, `name == id` forbidden. The fixture itself
         is an export-derived *superset* and may be wider than 47.
       - **F2** — generator = two layers: `fetch_stix(client)` (live export,
         manual commit-generation only, never invoked in tests/CI) and
         `build_fixture(stix_objects, provenance) -> bytes` (pure, deterministic;
         the determinism test feeds it the committed
         `tests/fixtures/stix_sample.json` + fixed provenance and asserts
         byte-identical output — live export never exercised in tests).
       - **F3** — provenance `generated_at` is date-only `YYYY-MM-DD` (never a
         timestamp); stable serialization (sorted keys, fixed indent,
         `allow_unicode`).
       - **F4** — `data_sources`: if `export_stix` attack-pattern objects carry
         no detection data sources, the generator enriches each technique at
         manual-generation time via `get_mitre_technique(include_threats=False)`
         (batched, cached under `tl:technique:*`); the unit test asserts
         non-empty `data_sources` for the 47 union techniques. Canary
         `T1518.001` (documented placeholder-fallback case) is a *soft* check:
         if absent from the generated fixture, the generator emits a WARN + a
         `map.md` note — **not** a ticket failure (covered by fallback level
         2 live).

**Tests:** `tests/unit/test_mitre_meta.py` (determinism + fallback order,
no MCP). Prior art: `tests/unit/test_m6_coverage.py` (pure functions over
fixture input, no DB).

**ADDITIVE-ONLY:** new files + appended loader code in `mitre_meta.py`; the
working enrich path and `threadlinqs_client.py`/`threadlinqs_cache.py` are not
rewritten.

## Answer

Resolved in commit `…` (ticket 01, push `cti_qc/main`).

Delivered:

- `backend/fixtures/mitre_attack_v15.yaml` — 780 techniques, provenance
  `version: 15.1`, `generated_at: 2026-08-15` (date-only, F3), `source:
  mitre_attack_stix_15.1`, `license: CC-BY-4.0`. No `name == id` placeholders.
- `backend/scripts/generate_mitre_v15_fixture.py` — two layers (F2): pure
  `build_fixture(stix_objects, provenance) -> bytes` (deterministic, byte
  identical across runs) and live `fetch_stix(client)` via generic
  `call_tool("export_stix", {...})`. New `--bundle PATH` mode reads a canonical
  MITRE STIX bundle file. `--check` compares `build_fixture(stix_sample)` to the
  committed fixture. Script header stays app-free (same convention as
  `smoke_threadlinqs.py`).
- `app/services/mitre_meta.py` — appended `_load_v15_fixture` (lru), 
  `fixture_technique`, `resolve_technique_meta` with the four-level fallback
  (HC-3): bundle names → injected `live_lookup` (client + 7-day cache closure
  wired by caller) → YAML v15 → hardcoded tables. No `threadlinqs_*` imports,
  no network.
- `tests/unit/test_mitre_meta.py` — 15 tests: F1 union=47 ⊆ fixture,
  F2 byte-determinism via committed `tests/fixtures/stix_sample.json` + fixed
  provenance, F3 date-only, F4 non-empty `data_sources`, HC-3 fallback order
  (levels 1/3/4 with `live_lookup=None`, level 2 with a fake callable).
- `tests/fixtures/stix_sample.json` — minimal STIX v15 sample (committed).

**Verified spec deviation (documented here and in map.md):** the live
Threadlinqs MCP v7.1.0 tool list (54 tools, Purple tier) has **no
`export_stix` tool**, so the fixture is generated from the canonical MITRE
ATT&CK v15.1 `enterprise-attack.json` STIX bundle via `--bundle` (same canonical
STIX source P4 specifies; the typed `export_stix` wrapper of ticket 06 does not
yet exist). Provenance `source` therefore honestly reads
`mitre_attack_stix_15.1` instead of the ticket's `threadlinqs_mcp_export_stix`.
`fetch_stix(client)`/`--write` remain for when the tool lands; `--bundle` needs
no API key. F4 required no enrichment: canonical v15.1 attack-pattern objects
carry `x_mitre_data_sources` for all 47 union techniques.

**Canary `T1518.001`:** present in the fixture as `Security Software
Discovery` (discovery) with non-empty data_sources — no WARN/map note needed.

**Test evidence:** `pytest tests/unit/test_mitre_meta.py` → 15 passed.
Regression sweep of the seven adjacent M6 suites (`test_m6_meta`,
`test_m6_coverage`, `test_m6_admiralty`, `test_m6_aql_emitter`,
`test_m6_tenants`, `test_m6_weights`, `test_technique_enrichment`) → 63 passed.
(`--cov-fail-under=60` reports a coverage failure only because a subset of the
suite was run in isolation; total-suite coverage is unaffected.)
