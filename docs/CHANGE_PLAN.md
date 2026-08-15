# CHANGE_PLAN.md — AdversaryGraph Threadlinqs + QRadar Extension

> Dependency order: M1 → M2 → M3 → M4 → M5 → M6
> Source of truth: docs/ARCHITECTURE_AUDIT.md (Phase 0)

---

## M1 — Threadlinqs MCP Client + Normalizer

| Aspect | Detail |
|--------|--------|
| **New files** | `backend/app/services/threadlinqs_client.py` — stdio MCP client, single long-lived session, initialize handshake, reconnect logic |
|  | `backend/app/services/threadlinqs_normalizer.py` — bundle → IOC list + behavioral list + metadata |
|  | `backend/app/services/relevance_scorer.py` — pure functions `score_threat(threat, tenant)` and `visible_ttps(threat, tenant, rulebook)`. `visible_ttps` counts a TTP only if an enabled rule covers it AND the tenant DRL for that rule's required log source ≥ 2. No I/O |
|  | `backend/app/services/ioc_classifier.py` — shared abused-legitimate whitelist util: classifies IOCs as malicious vs legitimate; whitelist on root legitimate owners only; attacker-created subdomains are malicious. Called by both normalizer (M1) and narrative extractor (M6) |
|  | `backend/app/services/circuit_breaker.py` — async decorator factory (half-open/open/closed, configurable threshold) |
|  | `backend/app/services/rate_limiter.py` — daily counter (5000/day) + obey 429 Retry-After from upstream; NOT a token bucket |
|  | `backend/app/services/threadlinqs_cache.py` — content-addressed Redis cache (SHA-256 of bundle ID), fetch-once score-per-tenant |
| **Existing files appended** | `backend/app/core/config.py` — append `threadlinqs_api_key`, `threadlinqs_enabled`, `threadlinqs_cache_ttl_hours` to Settings |
|  | `backend/app/core/redaction.py` — add `tl_` prefix + `THREADLINQS_API_KEY` to redaction patterns |
|  | `.env.example` — append `THREADLINQS_API_KEY=` |
|  | `backend/requirements.txt` — add `mcp>=1.0` (client+server same package) |
| **New deps** | `mcp` (already present for server; confirm client import works) |
| **Test plan** | 1. Normalize a real bundle fixture → assert IOC list has network+file entries only; behavioral list has technique tags; sectors/regions/ttps/actor non-empty. 2. `score_threat` against 3 seeded tenants → three distinct zone results. `visible_ttps` returns only TTPs where an enabled rule covers them and tenant DRL ≥ 2 for the required log source. 3. Circuit breaker: mock 3 failures → state opens → next call raises without invoking transport → half-open after cooldown. 4. Rate limiter: exhaust 5000 daily counter → next call blocked; mock 429 with Retry-After header → client sleeps and retries. 5. Cache: second fetch of same bundle ID returns cached; scoring per tenant produces distinct zone results. 6. Mock transport asserts `initialize` is called before first `call_tool`; dropped session triggers reconnect that recreates the session. 7. `ioc_classifier`: attacker subdomain on hosting platform → malicious; root legitimate domain → whitelisted. |
| **Rollback** | Delete new files; revert appended lines in config/redaction/.env.example/requirements.txt. No schema changes in M1. |

---

## M2 — Ingest Rules Parser + Fields Harvest

| Aspect | Detail |
|--------|--------|
| **New files** | `backend/app/services/rules_parser.py` — YAML loader, strip all string values and list elements, parse strictly to schema: building blocks, depends_on_bb (recursive), own_conditions, effective_detection_logic (kept as-is reference, not validated), custom fields (availability, adversary_control), reference sets. Parser does NOT validate regex or set degraded flags |
|  | `backend/app/services/fields_harvest.py` — extract field names from parsed rules for AQL emitter; reads `INDEXED_FIELDS` from `constants.py` (created in this module) |
|  | `backend/app/services/constants.py` — shared constants: `INDEXED_FIELDS = {"qid", "logsourceid", "devicetype", "domainid"}` (verified against QRadar AQL docs). `LAST` window is the mandatory perf anchor (emit blocks if missing); indexed-first ordering is a warning, not a block. `eventid` treated as high-cardinality semantic filter, not a system index |
|  | `backend/app/schemas/rules.py` — Pydantic models: `Rule`, `BuildingBlock`, `DetectionLogic`, `CustomField`, `ReferenceSet` |
| **Existing files appended** | `backend/requirements.txt` — add `pyyaml>=6.0` |
| **New deps** | `pyyaml` |
| **Test plan** | 1. Load the real rules YAML fixture → assert every string value and list element is stripped (no trailing spaces in ids, mitre arrays, criticality). 2. Assert depends_on_bb references parse correctly (chain integrity checked in M3). 3. Assert custom fields include availability + adversary_control attributes. 4. Parser preserves raw regex strings without validation (degraded detection deferred to M4 `regex_guard`). |
| **Rollback** | Delete new files; remove `pyyaml` from requirements.txt. |

---

## M3 — Schema + Building Block Resolver

| Aspect | Detail |
|--------|--------|
| **New files** | `backend/app/services/bb_resolver.py` — recursive resolver: walk depends_on_bb tree, build logic from each BB's `own_conditions` along the chain; use `effective_detection_logic` only as fallback when own_conditions is absent, tagged `logic_source=effective_fallback` vs `bb_chain`. Flatten custom fields, produce resolved detection |
|  | `backend/app/schemas/resolved_detection.py` — Pydantic model for fully resolved detection (merged fields, sources, logsource, logic_source tag, sufficiency metadata) |
| **Implementation note** | `INDEXED_FIELDS` lives in `constants.py` (created in M2). Values confirmed against official QRadar AQL docs via FireCrawl: real fast system fields are `qid`, `logsourceid`, `devicetype`, `domainid` plus the time window. `eventid` is a semantic high-cardinality filter, not a system index. `LAST` window is the mandatory perf anchor (block if missing); indexed-first is a warning, not a block |
| **Existing files appended** | None — M3 is pure logic consuming M2 output |
| **New deps** | None |
| **Test plan** | 1. Build a 3-level BB chain from fixture → resolver builds logic from `own_conditions` along chain; result tagged `logic_source=bb_chain`. 2. BB with missing own_conditions → falls back to `effective_detection_logic`, tagged `logic_source=effective_fallback`. 3. Circular dependency → raises `ResolutionError` with path trace. 4. Missing BB reference → raises `MissingBuildingBlock` with the dangling ID. 5. Resolved detection includes availability + adversary_control from deepest ancestor through to leaf. |
| **Rollback** | Delete new files. |

---

## M4 — AQL Emitter + Guardrails + FP Injection

| Aspect | Detail |
|--------|--------|
| **New files** | `backend/app/services/aql_emitter.py` — single internal IR with two input adapters: `from_resolved_detection` (M3 output) and `from_sigma_ast` (pySigma parse tree), both feeding one `emit` function. Emits QRadar AQL: mandatory `LAST` window (block if missing), explicit logsource filter, indexed field ordering is a warning not a block (reads `INDEXED_FIELDS` from M2 `constants.py`: `qid`, `logsourceid`, `devicetype`, `domainid`), availability/adversary_control sufficiency check |
|  | `backend/app/services/fp_injector.py` — injects FP overrides from tenant `fp_overrides` JSONB; real values only (hostnames, IPs, users), never hashes; appends `AND NOT` clauses |
|  | `backend/app/services/regex_guard.py` — validates ALL regex patterns in detection logic (owns degraded detection, moved here from M2). Degraded pattern → sets `copy_ready=false`, attaches `verify-pattern` warning to emitted rule. Called by emitter before emit |
|  | `backend/app/schemas/aql.py` — Pydantic models: `AQLRule`, `EmitterWarning`, `SufficiencyResult` |
| **Existing files appended** | `backend/requirements.txt` — add `pysigma>=0.11` (Sigma parsing only; NO pySigma-backend-qradar) |
| **New deps** | `pysigma` |
| **Test plan** | 1. `from_resolved_detection` → `emit` → output contains `LAST` window, logsource filter, indexed field (`INDEXED_FIELDS` from constants) is first predicate. 2. `from_sigma_ast` → `emit` → same AQL structure from Sigma input. 3. Rule with insufficient availability → `copy_ready=false`, sufficiency warning attached. 4. `regex_guard` finds degraded regex → `copy_ready=false`, `verify-pattern` warning. 5. FP injection with tenant overrides → `AND NOT` clauses use real values (IP, hostname), no hash literals. |
| **Rollback** | Delete new files; remove `pysigma` from requirements.txt. |

---

## M5 — Tenants + RBAC + 3-Tenant Seed

| Aspect | Detail |
|--------|--------|
| **New files** | `backend/app/api/routes/tenants.py` — CRUD router for tenant profiles; `GET /tenants`, `GET /tenants/{id}`, `PUT /tenants/{id}`; gated by `tenants_enabled` toggle + `tenants:manage` permission |
|  | `backend/app/api/routes/qradar.py` — QRadar conversion endpoints: `POST /qradar/convert` (single rule), `POST /qradar/batch` (all rules for tenant); gated by `qradar_enabled` + `qradar:convert` |
|  | `backend/app/api/routes/ingest.py` — Threadlinqs ingest endpoints: `POST /ingest/pull` (trigger fetch), `GET /ingest/status`; gated by `ingest_enabled` + `ingest:write` |
|  | `backend/app/services/tenant_seed.py` — idempotent seeder: 3 tenants (finance, energy, critical_infrastructure), geo=KZ, siem=QRadar 7.5, is_active=true; runs at startup after schema extension |
|  | `backend/app/services/schema_extend.py` — idempotent `ADD COLUMN IF NOT EXISTS` for client_profiles: `siem_version`, `geo`, `rulebook_version`, `drl_matrix` (JSONB), `fp_overrides` (JSONB), `relevance_config` (JSONB), `is_active` (boolean). All columns nullable with server_default so `create_all` on fresh DB and `ALTER IF NOT EXISTS` on existing DB produce identical schema; existing routers untouched; new code uses explicit column lists, never SELECT * (closes audit risk R1) |
|  | `frontend/src/api/hermes.ts` — new API namespaces: `tenantsApi`, `qradarApi`, `ingestApi`, `threadlinqsApi`; TypeScript interfaces for tenant, rule, AQL output |
|  | `frontend/src/store/tenantStore.ts` — separate Zustand store for active tenant; persists to localStorage key `adversarygraph-tenant-v1`; invalidates React Query cache on tenant change |
|  | `frontend/src/components/Layout/TenantSwitcher.tsx` — dropdown rendered at TOP of sidebar, above nav list (not a nav item). Reads/writes `tenantStore`; default = first `is_active` profile. On change: sets `activeTenant` in store; every existing router that accepts `client_profile_id` reads it from this store |
|  | `frontend/src/pages/Tenants.tsx` — tenant list + detail view (lazy-loaded) |
|  | `frontend/src/pages/QRadarRules.tsx` — rules TABLE: list + filters + "Open in Studio" button per rule. NOT the AQL editor (lazy-loaded) |
|  | `frontend/src/pages/AQLStudio.tsx` — SEPARATE page with three panels: Input (rule source), Output (emitted AQL), Field-mapping (indexed/custom fields). Client selector dropdown at top reads `tenantStore`. (lazy-loaded) |
|  | `frontend/src/pages/IngestDashboard.tsx` — ingest status + manual pull trigger (lazy-loaded) |
| **Existing files appended** | `backend/app/core/config.py` — append toggles: `qradar_enabled`, `threadlinqs_enabled` (alias, already in M1), `ingest_enabled`, `tenants_enabled` (all default `false`) |
|  | `backend/app/models/sector.py` — add new `Mapped[Optional[...]]` columns to `ClientProfile`: `siem_version`, `geo`, `rulebook_version`, `drl_matrix`, `fp_overrides`, `relevance_config`, `is_active`. All nullable with `server_default` so existing rows remain valid |
|  | `backend/app/models/auth.py` — document accepted roles: `admin`, `senior_analyst`, `junior_analyst`, `viewer`; no schema change (role is already a free string) |
|  | `backend/main.py` lines 27+274–326 — import + include_router for `tenants`, `qradar`, `ingest` routers with `_module_required` deps |
|  | `frontend/src/components/Layout/Sidebar.tsx` lines 30–105 — append nav items: Tenants (module `tenants_enabled`, permission `tenants:manage`), QRadar Rules (module `qradar_enabled`, permission `qradar:read`), AQL Studio (module `qradar_enabled`, permission `qradar:convert`), Ingest (module `ingest_enabled`, permission `ingest:write`). Insert `<TenantSwitcher />` above the nav list |
|  | `frontend/src/App.tsx` — add `<Route>` entries for Tenants, QRadar Rules, AQL Studio, Ingest wrapped in `<RoleGate>` |
|  | `frontend/src/api/client.ts` — add `tl_` prefix + `THREADLINQS` to redaction patterns (frontend log sanitizer if present) |
|  | `.env.example` — append `QRADAR_ENABLED=false`, `INGEST_ENABLED=false`, `TENANTS_ENABLED=false` |
| **New deps** | None beyond M1–M4 |
| **Decision: tenant-scoped existing routers** | An axios request interceptor (or wrapper) in `hermes.ts` injects the active `client_profile_id` from `tenantStore` into outgoing requests — including EXISTING routers (rag, sector, threat_radar, etc.) — so tenant switch re-scopes existing pages without editing RAGAssistant or similar components (additive-only). FastAPI ignores the extra query/body param on routers that do not declare it (system, auth); verified by testing that undeclared params are silently dropped |
| **Test plan** | 1. Startup with empty DB → `schema_extend` adds columns idempotently (run twice, no error); columns are nullable with defaults. 2. Seed inserts 3 tenants → `client_profiles` has finance/energy/critical_infrastructure rows with geo=KZ, siem=QRadar 7.5, is_active=true. 3. `score_threat` (from M1 `relevance_scorer`) against all 3 tenants → three distinct zone results reflecting each tenant's `relevance_config` and `drl_matrix`. 4. AccessGroup with `qradar:convert` can POST `/qradar/convert`; group without it gets 403. 5. Tenant change in frontend store invalidates cached queries (mock React Query). 6. Switching tenant in `TenantSwitcher` sends new `client_profile_id` on subsequent API calls. 7. Verify FastAPI ignores extra `client_profile_id` param on routers that don't declare it (system, auth return 200, no error). |
| **Rollback** | Delete new files; revert appended lines in main.py, config.py, sector.py, Sidebar.tsx, App.tsx, .env.example. Run `ALTER TABLE client_profiles DROP COLUMN IF EXISTS` for each added column. |

---

## M6 — AI Extraction for Third-Party Reports

| Aspect | Detail |
|--------|--------|
| **New files** | `backend/app/services/narrative_extractor.py` — LLM-based extraction from uploaded PDF/text reports; produces IOC list + behavioral list tagged `confidence=extracted`; secondary source, used only when indicators block is empty or for third-party reports |
|  | `backend/app/api/routes/report_ingest.py` — `POST /ingest/report` (upload file), gated by `ingest_enabled` + `ingest:write` |
|  | `backend/app/schemas/extracted_intel.py` — Pydantic models for extracted IOCs, behavioral indicators, confidence tags |
| **Existing files appended** | `backend/main.py` lines 27+274–326 — import + include_router for `report_ingest` |
|  | `frontend/src/components/Layout/Sidebar.tsx` — append "Report Upload" nav item under Ingest section |
|  | `frontend/src/App.tsx` — add `<Route>` for report upload page |
|  | `frontend/src/pages/IngestDashboard.tsx` — add upload tab/section |
| **New deps** | None (uses existing LLM client from `backend/app/core/config.py` settings) |
| **Test plan** | 1. Upload a sample report text with known IOCs → extractor returns IOC list with `confidence=extracted`. 2. Bundle WITH indicators block → narrative extractor is NOT called (primary path). 3. Bundle with EMPTY indicators block → narrative extractor IS called, results tagged lower confidence. 4. Abused-legitimate filter uses shared `ioc_classifier` (from M1): attacker subdomain on hosting platform → malicious; root legitimate domain → whitelisted. Same classifier, same results as structural normalizer. |
| **Rollback** | Delete new files; revert appended lines in main.py, Sidebar.tsx, App.tsx. |

---

## Cross-Cutting Concerns

| Concern | Approach |
|---------|----------|
| **No Alembic** | Schema extension via idempotent `ADD COLUMN IF NOT EXISTS` SQL in `schema_extend.py`, called during lifespan startup after `Base.metadata.create_all` |
| **Column defaults (R1)** | All new `Mapped[]` columns on `ClientProfile` are `Optional`, nullable, with `server_default`. `create_all` on fresh DB and `ALTER IF NOT EXISTS` on existing DB produce identical schema. Existing routers untouched; new code uses explicit column lists, never `SELECT *` |
| **RBAC** | Role remains a string on `UserAccount`; add `admin`, `senior_analyst`, `junior_analyst` as accepted values alongside existing `viewer`. Fine-grained rights via `AccessGroup.permissions` JSONB: `qradar:read`, `qradar:convert`, `ingest:write`, `tenants:manage`, `threadlinqs:read` |
| **Sidebar gating** | Each new nav item specifies `module` (maps to settings toggle) + `permission` (maps to AccessGroup). `canViewNavItem()` already handles this pattern. `TenantSwitcher` sits above the nav list, not as a nav item |
| **Frontend state** | Tenant context in separate Zustand store (`tenantStore.ts`) with separate localStorage key. Main `useAppStore` untouched. React Query cache invalidated on tenant switch. Every router accepting `client_profile_id` reads from `tenantStore` |
| **API namespace** | All new API calls in `frontend/src/api/hermes.ts`, not in the 4042-line `client.ts` |
| **Redaction** | Backend: add `tl_` prefix and `threadlinqs_api_key` to `redaction.py` patterns. Frontend: add same to `hermes.ts` request interceptor |
| **Normalizer priority** | Indicators block is PRIMARY (network→IOC, file→IOC, behavioral→hunt seeds). Narrative mining is SECONDARY (third-party reports or empty indicators only), tagged `confidence=extracted` |
| **Abused-legitimate** | Shared `ioc_classifier.py` (M1) used by both normalizer and narrative extractor. Whitelist on root legitimate owners only; attacker-created subdomains are malicious and blockable |
| **Indexed fields** | Single constant set `INDEXED_FIELDS` in `constants.py` (M2): `{qid, logsourceid, devicetype, domainid}` — verified against QRadar AQL docs. `eventid` is high-cardinality semantic filter, not a system index. `LAST` window is the mandatory perf anchor (block if missing); indexed-first is a warning, not a block |
| **Degraded regex** | Owned entirely by `regex_guard.py` (M4). M2 parser preserves raw strings without validation. Guard runs before AQL emit and sets `copy_ready=false` + `verify-pattern` warning |
| **AQL emitter IR** | One internal IR with two input adapters (`from_resolved_detection`, `from_sigma_ast`) feeding a single `emit` function. No parallel emitters |

---

## Integration Test (End-to-End)

| Step | Assert |
|------|--------|
| 1. Startup | `schema_extend` adds columns (nullable, with defaults); `tenant_seed` inserts 3 tenants |
| 2. Load real rules YAML | All values stripped; BB chains resolve via `own_conditions` (or `effective_fallback`); custom fields have availability + adversary_control |
| 3. Normalize real Threadlinqs bundle | IOC list (network+file); behavioral list (technique tags); sectors, regions, ttps, actor populated; `ioc_classifier` applied |
| 4. Score threat × 3 tenants | `score_threat` + `visible_ttps` produce three distinct zone results reflecting finance/energy/critical_infrastructure relevance configs + DRL thresholds |
| 5. Emit AQL for resolved rule | Valid AQL with LAST window, logsource, indexed-first (`INDEXED_FIELDS`), FP injection, sufficiency check; degraded regex flagged by `regex_guard` |
| 6. Upload third-party report | Narrative extraction produces lower-confidence IOCs; shared `ioc_classifier` applies same abused-legitimate filter |
| 7. Tenant switch (optional e2e) | `TenantSwitcher` sets new tenant → subsequent API calls send new `client_profile_id` → React Query cache invalidated |

---

## Locked decisions v2

> These override earlier scope. Recorded 2026-07-28.

1. **Primary product goal is QUARTERLY threat-hunt hypotheses** (3-month cycle demanded by clients), not one-off alerts. Everything else serves hypothesis generation and the quarterly hunt loop.
2. **Attack Simulation / emulation is OUT of scope for now.** Do not build or prioritize it.
3. **Reference end-to-end success case:** quarterly hypothesis (e.g. botnet spread) → retro-hunt over historical telemetry (e.g. DNS logs) → incident registered → forensics → client report. The product must make this loop repeatable and measurable.
4. **Existing AdversaryGraph routers `retrohunt`, `investigation`, `evidence_graph`, `export`, `threat_hunting`, `threat_hunting_ai` already cover most of that loop.** We ADD glue (coverage analyzer, agent skills registry, Agents page) and LLM wrappers; we do NOT rewrite them (additive-only).
5. **Add a dedicated Agents tab backed by a skills registry:** specialized agents with pre-written skills, not one monolithic LLM call. Seed skills come from the Feedly CTI Prompt Library zip the human provided; map files to skills, do not author prompts from scratch.
6. **Remember for later automation:** the Zeltser CTI brief template is the client/executive report template; the playingwithpackets chokepoints concept feeds hypothesis prioritization (a hypothesis on a chokepoint technique, i.e. a rule whose key field has `adversary_control` LOW, gets a confidence bonus because the detection is durable).

See `docs/HYPOTHESIS_ENGINE.md` (quarterly loop, blind-spot types, priority formula) and `docs/AGENT_SKILLS.md` (skills registry read by M7/M8).
