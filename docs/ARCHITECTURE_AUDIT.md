# ARCHITECTURE_AUDIT.md — AdversaryGraph v6.5.0

> Phase 0 output. Read-only recon of the repo as-is.
> Date: 2026-07-26 | Auditor: Cline (Opus 4.6)

---

## 1. Stack & Versions

| Layer | Technology | Version / Notes |
|-------|-----------|-----------------|
| Backend | Python / FastAPI | 3.11.9 / FastAPI (async, Uvicorn) |
| ORM | SQLAlchemy (async) | Mapped-column style, Alembic implied |
| Database | PostgreSQL | 18.4, async via `asyncpg` |
| Task queue | Celery + Redis | `redis://localhost:6379/0` |
| Frontend | React + TypeScript | React 18.3, TS 5.7, Vite 6 |
| State | Zustand 5 + React Query 5 | Single store `useAppStore`, persists to localStorage |
| UI | Tailwind CSS 3.4 + Radix UI | clsx, tailwind-merge, cmdk palette |
| Tables | @tanstack/react-table 8 | With react-virtual 3 |
| Graphs | @xyflow/react 12, d3 7, Recharts 3 | |
| Editor | Monaco Editor (React wrapper) | |
| Auth | Local (bcrypt) + external providers | Session-based, RBAC via roles + access groups |
| MCP server | `mcp.server.fastmcp.FastMCP` | stdio transport, 4 tools |
| Platform version | 6.5.0 | `VERSION` file at repo root |

---

## 2. How the App Boots

**Entry point:** `backend/main.py` (362 lines)

1. **Model registration (lines 15–26):** 12 model modules imported for side-effect SQLAlchemy `Base` metadata registration:
   `sector_packs`, `retrohunt`, `knowledge`, `asset_surface`, `simulation`, `cve`, `auth`, `evidence_graph`, `threat_radar`, `threat_hunting`, `rag`, `query_library`.

2. **Lifespan (asynccontextmanager):** Creates DB tables via `Base.metadata.create_all` on startup; no explicit teardown beyond engine disposal.

3. **FastAPI app creation:** Title "AdversaryGraph API", version from `app.core.version`.

4. **Middleware stack (in order):**
   - Custom `request_logging_middleware` (`@app.middleware("http")`) — assigns/validates `X-Request-ID`, records observability metrics, logs every request.
   - `CORSMiddleware` — origins from `settings.cors_allowed_origins` (default `*`).
   - `RateLimitMiddleware` — from `app.core.rate_limit`.

5. **Route registration (lines 274–326):** 28 routers imported from `app.api.routes` and mounted with `app.include_router()`, all under prefix `/api`. Access gated by `_module_required` / `_one_module_required` / `_auth_required` dependency helpers.

---

## 3. Route Registry — All 28 Routers

| # | Router module | Prefix | Access dependency |
|---|--------------|--------|-------------------|
| 1 | `auth` | `/api` | None (public) |
| 2 | `attack` | `/api` | `_one_module_required("discover","navigator","compare","apt_library","investigation","threat_hunting","attack_simulation","asset_surface","evidence_graph","threat_radar")` |
| 3 | `apt` | `/api` | `_one_module_required("apt_library","compare","investigation","threat_radar","sector_intel","evidence_graph","threat_hunting")` |
| 4 | `analyze` | `/api` | `_one_module_required("ai_analysis","reports_research","investigation")` |
| 5 | `asset_surface` | `/api` | `_module_required("asset_surface")` |
| 6 | `sync` | `/api` | `_auth_required` |
| 7 | `export` | `/api` | `_auth_required` |
| 8 | `ioc` | `/api` | `_one_module_required("ioc_library","investigation","threat_hunting")` |
| 9 | `cve` | `/api` | `_module_required("cve_library")` |
| 10 | `emb3d` | `/api` | `_module_required("emb3d")` |
| 11 | `evidence_graph` | `/api` | `_module_required("evidence_graph")` |
| 12 | `layers` | `/api` | `_one_module_required("navigator","compare")` |
| 13 | `malwaregraph` | `/api` | `_module_required("malware_analysis")` |
| 14 | `observability` | `/api` | `_auth_required` |
| 15 | `operations` | `/api` | `_auth_required` |
| 16 | `pipeline` | `/api` | `_auth_required` |
| 17 | `query_library` | `/api` | `_module_required("query_library")` |
| 18 | `rag` | `/api` | `_module_required("ai_analysis")` |
| 19 | `retrohunt` | `/api` | `_module_required("retrohunt")` |
| 20 | `sector` | `/api` | `_module_required("sector_intel")` |
| 21 | `simulation` | `/api` | `_module_required("attack_simulation")` |
| 22 | `statistics` | `/api` | `_auth_required` |
| 23 | `system` | `/api` | None (public health/version) |
| 24 | `knowledge` | `/api` | `_module_required("knowledge")` |
| 25 | `troubleshooting` | `/api` | `_auth_required` |
| 26 | `threat_hunting` | `/api` | `_module_required("threat_hunting")` |
| 27 | `threat_hunting_ai` | `/api` | `_module_required("threat_hunting")` |
| 28 | `threat_radar` | `/api` | `_module_required("threat_radar")` |

**Registration seam:** To add a new router, import it from `app.api.routes` at the top of `main.py` (line 27 area), then add an `app.include_router(module.router, prefix="/api", dependencies=[...])` call in the block at lines 274–326.

---

## 4. Existing MCP Server

**Location:** `backend/app/mcp_server.py` (728 lines) — **NOT** at `backend/mcp_server.py`.

**Architecture:** Uses `FastMCP` from `mcp.server.fastmcp`. Runs exclusively over stdio transport. Acts as a thin, advisory-only facade that proxies requests to the AdversaryGraph FastAPI backend via HTTP (default `http://127.0.0.1:3000`).

**Four tools registered** via `server.add_tool()` in `_build_mcp_server()` (lines 668–697):

| Tool | Params | Annotation | Purpose |
|------|--------|------------|---------|
| `search_intelligence` | query, source_types, domain, client_profile_id, limit | read_only | Search IOC/CVE/ATT&CK/report/RAG corpus |
| `ask_intelligence` | query, source_types, domain, client_profile_id, limit | advisory_recorded | Ask governed AI for citation-bound answer |
| `get_indexed_entity` | source_type, source_id | read_only | Read one sanitized indexed entity |
| `propose_navigator_layer` | objective, domain, client_profile_id | advisory_recorded | Generate an ATT&CK Navigator layer |

**`client_profile_id` validation:** `_validated_profile_id()` helper validates the parameter before use in each tool. The profile is looked up from the `client_profiles` table.

---

## 5. EXTENSION SEAMS ★★★ (Most Important Finding)

### 5a. Backend Route Seam
- **File:** `backend/main.py`, lines 27 (imports) + 274–326 (include_router calls)
- **Pattern:** Import router module from `app.api.routes`, call `app.include_router(module.router, prefix="/api", dependencies=[...])`
- **Route `__init__.py`:** Empty — no auto-discovery; registration is explicit in `main.py`

### 5b. Frontend Sidebar/Nav Seam
- **File:** `frontend/src/components/Layout/Sidebar.tsx`, lines 30–105
- **Pattern:** Static `navSections: NavSection[]` array with 7 sections. Each item has `{ to, label, icon, module, permission? }`. Items are filtered by `canViewNavItem()` which checks user permissions and module access.
- **Sections:** Workspace, Intelligence, Analyze & Investigate, Evidence, Platform, Learn & Support (+ one more)
- **To add a nav item:** Append to the appropriate section in the `navSections` array

### 5c. Frontend Routing Seam
- **File:** `frontend/src/App.tsx` (~341 lines)
- **Pattern:** React Router v6 with lazy-loaded page components. Each route wrapped in `<RoleGate module="..." permission="...">`.
- **To add a page:** Create lazy-loaded component, add `<Route>` in `App.tsx`, wrap in `<RoleGate>`

### 5d. Frontend API Client Seam
- **File:** `frontend/src/api/client.ts` (~4042 lines)
- **Pattern:** Namespace objects (e.g., `sectorApi`, `ragApi`) with methods wrapping axios calls. TypeScript interfaces defined at top.
- **To add API calls:** Add new interface types + new API namespace object

### 5e. Frontend State Seam
- **File:** `frontend/src/store/index.ts`
- **Pattern:** Single Zustand store `useAppStore`. Persists selected slices to localStorage key `adversarygraph-docker-workbench-v1`.
- **To add state:** Add new slice to the store (or create a separate store for tenant context)

### 5f. Model Registration Seam
- **File:** `backend/main.py`, lines 15–26
- **Pattern:** Import model module for side-effect: `import app.models.new_module as _new_module  # noqa: F401`

---

## 6. ClientProfile — EXISTING (Extend, Do Not Duplicate)

**Model location:** `backend/app/models/sector.py`, lines 61–76

**Table:** `client_profiles`

**Current schema:**
```python
class ClientProfile(Base):
    __tablename__ = "client_profiles"
    id:            Mapped[int]           # PK, auto-increment
    name:          Mapped[str]           # String(255)
    sector:        Mapped[str]           # String(120), indexed
    region:        Mapped[str]           # String(120), default ""
    technologies:  Mapped[list]          # JSONB, default []
    crown_jewels:  Mapped[list]          # JSONB, default []
    notes:         Mapped[str]           # Text, default ""
    created_at:    Mapped[datetime]      # server_default=now()
    updated_at:    Mapped[datetime]      # server_default=now(), onupdate=now()
```

**Usage across codebase (44 references in 8 files):**
- `backend/app/api/routes/rag.py` — CRUD at `/profiles`, `/profiles/{profile_id}`; `client_profile_id` in request bodies for RAG search/assist
- `backend/app/services/rag.py` — Looks up `ClientProfile` by ID, builds business context for embedding queries
- `backend/app/mcp_server.py` — Parameter in all 4 MCP tools; `_validated_profile_id()` helper
- `frontend/src/api/client.ts` — TypeScript interface field `client_profile_id?: number`
- `frontend/src/components/Navigator/RAGAssistant.tsx` — Sends `client_profile_id` in RAG calls

**Decision:** The `client_profiles` table ALREADY exists and is the canonical client concept. We EXTEND it with `siem_version`, `rulebook_version`, `drl_matrix`, `fp_overrides`, `relevance_config`, `geo`, `is_active` columns via an Alembic migration. We do NOT create a parallel `client_tenants` table.

---

## 7. Feeds Management / Sync Format

**File:** `backend/app/api/routes/sync.py`

**Supported sources:**
| Source | Format | Mechanism |
|--------|--------|-----------|
| `mitre-attack` | STIX 2.1 bundles | Celery task, daily cron at 03:00 UTC |
| `ioc-intelligence` | ThreatFox / Malpedia / AlienVault OTX / custom | `sync_all_ioc_sources` service |
| `cve-intelligence` | NVD CVE API 2.0 + CISA KEV | `sync_all_cve_sources` service |

**Endpoints:** `POST /sync/trigger` (MITRE only), `POST /sync/ioc`, `POST /sync/cve`, `POST /sync/dynamic-db`. All require `manage_feeds` permission.

**No TAXII endpoint exists.** Feed ingestion is pull-based via scheduled Celery tasks, not push-based. Threadlinqs integration will be a NEW pull-based service, not a modification of existing sync.

---

## 8. Conventions

### 8a. Typing
- Backend: All models use SQLAlchemy `Mapped[]` type annotations. Services use standard Python type hints. Pydantic models for request/response schemas.
- Frontend: TypeScript strict mode. Interfaces defined in `api/client.ts`.

### 8b. Error Handling
- Backend: FastAPI exception handlers; routes return `JSONResponse` with status codes. Services raise exceptions caught by route handlers.
- Pattern: `try/except` with specific exception types; generic 500 for unexpected errors.

### 8c. Logging
- `SensitiveDataFilter` redacts credentials from logs before handlers.
- Format: `%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s %(message)s`
- Two handlers: stdout `StreamHandler` + `RotatingFileHandler` (`adversarygraph-api.log`).

### 8d. Redaction
- File: `backend/app/core/redaction.py`
- Three regex patterns: Bearer/Basic tokens, URL-embedded credentials, key=value sensitive assignments (access_token, refresh_token, api_key, password, secret, authorization, cookie, session).
- **Threadlinqs API key MUST be added to the redaction pattern list.**

### 8e. Testing
- Framework: pytest + pytest-asyncio
- Structure: `backend/tests/unit/` (49 files) + `backend/tests/integration/` (30 files)
- Conventions: Module-level functions (no classes), `test_` prefix, `@pytest.mark.asyncio` for async, `monkeypatch` for patching, fake/stub classes prefixed with `_`, plain `assert` statements, `pytest.raises(match=...)` for exception testing.
- Frontend: Playwright (e2e) in `frontend/tests/`.
- Config: `backend/pytest.ini` + `backend/pyproject.toml`.

### 8f. Auth/RBAC
- Models in `backend/app/models/auth.py`: `UserAccount` (role field: default "viewer"), `AuthSession`, `AccessGroup` (JSONB permissions + modules), `UserAccessGroup` (M2M join).
- Roles are string-based on `UserAccount.role`. Access groups supplement with fine-grained permissions.
- Route-level: `_module_required` / `_auth_required` dependency helpers.
- Frontend: `<RoleGate module="..." permission="...">` wraps every route.

---

## 9. Existing Routers That Must NOT Be Recreated

The tenant layer REUSES these by passing `client_profile_id` through — it does NOT duplicate their logic:

| Router | Covers |
|--------|--------|
| `threat_radar` | Threat scoring, radar visualization |
| `threat_hunting` + `threat_hunting_ai` | Hunting queries, AI-assisted hunting |
| `query_library` | Saved queries |
| `sector` | Sector intel, client profiles CRUD, actor observations |
| `pipeline` | Processing pipeline |
| `operations` | Operational monitoring |
| `observability` | System observability |
| `troubleshooting` | Diagnostic tools |
| `retrohunt` | Retroactive hunting signals |
| `simulation` | Attack simulation |
| `evidence_graph` | Evidence graph construction |
| `knowledge` | Knowledge library |
| `ioc` | IOC library |
| `layers` | Navigator layers |
| `rag` | RAG search/assist + profile-scoped queries |
| `sync` | Feed management |
| `attack` | ATT&CK data |
| `apt` | APT group library |
| `analyze` | AI analysis |
| `cve` | CVE library |
| `export` | Data export |
| `statistics` | Statistics |
| `system` | Health, version |
| `auth` | Authentication |

---

## 10. Docker / Infrastructure

**`docker-compose.yml` services:** Backend (FastAPI), Frontend (React/Vite via nginx), PostgreSQL, Redis, Celery worker(s). Nginx reverse proxy in `nginx/nginx.conf`.

**Helm chart:** `helm/adversarygraph/` for Kubernetes deployment.

---

## 11. Pydantic Settings (Extension Point for Threadlinqs)

**File:** `backend/app/core/config.py` (224 lines)

Key existing fields: `database_url`, `db_*`, `redis_url`, `anthropic_api_key`, `openai_api_key`, `gemini_api_key`, `minimax_api_key`, `local_llm_*`, `rag_*`, `threat_hunting_ai_*`, `cors_allowed_origins`, `auth_enabled`, `log_level`, module toggles, etc.

**Seam:** APPEND `threadlinqs_api_key: str = ""` to the Settings class. Do not rewrite existing fields.

**`.env.example`** lists all env vars with placeholder values. APPEND `THREADLINQS_API_KEY=` to it.

---

## 12. RISKS & OPEN QUESTIONS

### Risks

| # | Risk | Mitigation |
|---|------|------------|
| R1 | Extending `client_profiles` table with 6+ new JSONB columns may break existing RAG/sector queries that SELECT * | Use explicit column selection in new code; migration adds columns with defaults (NULL/empty JSONB) so existing rows remain valid |
| R2 | No Alembic migration folder found in repo — table creation is via `Base.metadata.create_all` in lifespan | Need to confirm: does the project use Alembic at all? If not, migrations must be SQL scripts or a new Alembic setup. Either way, the additive-only constraint means we ADD columns, never ALTER existing ones |
| R3 | Single Zustand store + localStorage persistence — adding tenant context must not corrupt existing persisted state | Use a separate Zustand store or a new localStorage key for tenant state |
| R4 | The `mcp` Python SDK (`mcp.server.fastmcp`) is already a dependency — but the CLIENT SDK (`mcp.client`) may not be installed | Check `requirements.txt` for `mcp` package; the server SDK and client SDK are in the same package (`mcp`) |
| R5 | Threadlinqs rate limit (Purple = 5000 req/day) across 18 tenants = ~278 req/tenant/day max | Implement content-addressed caching + shared cache (same threat bundle serves all tenants) |
| R6 | 4042-line `api/client.ts` is a monolith — adding more interfaces/namespaces increases risk of merge conflicts | Keep new API namespaces at the bottom; consider a separate file if it exceeds maintainability |

### Open Questions for Human

| # | Question |
|---|----------|
| Q1 | **Alembic:** Does the project use Alembic for migrations? I see no `alembic/` folder or `alembic.ini`. If not, what is the preferred migration strategy? |
| Q2 | **Module toggles:** The Settings class has module toggle fields (e.g., `rag_enabled`, `threat_hunting_ai_enabled`). Should new modules (QRadar, Threadlinqs, Ingest) have their own toggle flags? |
| Q3 | **Auth integration:** The existing RBAC uses `UserAccount.role` + `AccessGroup.permissions`. For the 4 new roles (admin, senior_analyst, junior_analyst, viewer), should we extend the existing role enum or create new access groups? The existing `role` field is a plain string — "viewer" is the default. |
| Q4 | **Frontend module gating:** The `canViewNavItem` function checks `module` and `permission` against the user. What are the existing module toggle names from the backend settings? Need to map new nav items to module flags. |
| Q5 | **Threadlinqs MCP transport:** The task says to use `mcp` Python SDK with `StdioServerParameters + stdio_client`. Should the Threadlinqs MCP client connect via stdio (spawning `npx intelthreadlinqs-mcp`)? Or is there an SSE/HTTP endpoint? Need the exact package name and transport. |
| Q6 | **Existing profile data:** Are there already ClientProfile rows in the DB (e.g., for KEGOC)? If so, the migration must preserve them and backfill new columns with sensible defaults. |
| Q7 | **The real rules/fields files:** The task references a "real rules file with Russian headers" and "real 346-rule YAML". Are these files in the repo or will they be provided separately? I don't see them in the current tree. |
| Q8 | **pySigma version:** The task says to add pySigma to requirements.txt. Which version? And confirm: we do NOT add `pySigma-backend-qradar` (will write our own emitter). |

---

## 13. Session State

**What's done:** PHASE 0 complete — full repo recon, all findings documented.

**What's next:** Awaiting human review of this audit + answers to open questions. Then PHASE 1 (CHANGE_PLAN.md) in PLAN mode.

**Key decisions confirmed:**
- `client_profiles` EXISTS → EXTEND it, do NOT create `client_tenants`
- Frontend EXISTS at `frontend/src/` → React 18 + TS + Vite
- MCP server is at `backend/app/mcp_server.py` (not `backend/mcp_server.py`)
- Route registration is explicit in `main.py` (no auto-discovery)
- Sidebar nav is a static array in `Sidebar.tsx`
- No Alembic detected — migration strategy TBD
