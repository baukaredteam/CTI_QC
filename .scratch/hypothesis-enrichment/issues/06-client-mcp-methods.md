# 06 — Threadlinqs client MCP methods

**Type:** task
**Status:** partially-implemented
**Blocked by:** None — can start immediately

**What to build:** Four new read-only methods on the Threadlinqs client so the
pipeline can fetch hunt enrichment without touching the existing tool call
path. Every method is wrapped by the existing `_breaker` and result parser, and
degrades gracefully (empty result, no exception) when `threadlinqs_enabled`
is false or the breaker is open.

**Acceptance criteria:**

- [ ] `ThreadlinqsClient` gains, additively:
      - `get_threat_hunting_bundle(threat_id, simulation_limit=3, pivot_limit=25)`
        — the bundle enrichment source for ticket 08 (P5);
      - `predict_mitre_transitions(technique_id, direction='forward', top_n=5,
        basis='any')` — the prediction source for ticket 09 (P6);
      - `export_stix(threat_id=None, actor=None, cve_id=None, include_osint=False)`
        — the canonical STIX source for the fixture generator (ticket 01, P4);
      - `get_attack_flow(threat_id)` — supporting method for the prediction
        basis `attack_flow`.
- [ ] Each method goes through the existing `_breaker` and `_parse_tool_result`;
      on `threadlinqs_enabled=False`, breaker open, or timeout it returns the
      method's empty default (empty dict/list) — never an exception.
- [ ] No existing client method or call path is modified (ADDITIVE-ONLY).
- [ ] Unit tests `tests/unit/test_threadlinqs_client.py` assert each new
      method's success shape with a mocked transport and its empty-result
      fallback when disabled.

**Tests:** `tests/unit/test_threadlinqs_client.py`. Prior art: existing client
tests using the mocked transport seam.

**ADDITIVE-ONLY:** appended methods only; the working
`threadlinqs_client.py` logic is not rewritten.

**Note (fog):** confirm the four tool names against the real Threadlinqs tool
list (54 tools, Purple tier) while implementing; adapt argument names to the
actual MCP schema if they differ, keeping the public method signatures above.

---

## Protocol reconciliation (verified against v7.1.0 source)

Protocol verified against the authoritative `intelthreadlinqs-mcp@7.1.0` tool
registry (`dist/index.js` installed globally via npm).

### Implemented (3 methods)

| Public method | Actual MCP tool name | inputSchema args | Result envelope |
|---|---|---|---|
| `get_threat_hunting_bundle(threat_id, simulation_limit=3, pivot_limit=25)` | `get_threat_hunting_bundle` | `{threat_id: string}` required — **only threat_id** (no simulation_limit/pivot_limit in v7.1.0 schema) | `{threat, iocs, detections, similar_threats, simulations, infrastructure_pivots, meta}` (sub-calls fail → null) |
| `predict_mitre_transitions(technique_id, direction=forward, top_n=5, basis=any)` | `predict_mitre_transitions` | `{technique_id: string} required; direction: enum[forward,backward]; top_n: number ≤10; basis: enum[any,attack_flow,simulations]` — **1:1 with public signature** | `{predicted_next_techniques: array, predicted_prev_techniques: array}` |
| `get_attack_flow(threat_id)` | `get_attack_flow` | `{threat_id: string} required` — **1:1** | `{attack_flow: object, nodes: array, edges: array}` |

### NOT implemented (1 method — NEEDS_DECISION)

| Public method | Status | Reason |
|---|---|---|
| `export_stix(threat_id=None, actor=None, cve_id=None, include_osint=False)` | **ABSENT in v7.1.0** | The server source itself says: "STIX export could be a roadmap ask (the roadmap mentions it)." No real tool exists → schema unavailable → contract NOT invented per the user's gate: "Если real tool list/schema недоступны, не выдумывай контракт." |

### Canonical disabled flag

`settings.threadlinqs_enabled` (config.py:191, default `False`) — the existing
flag used by callers (feed_scanner.py:153, management_service.py:478). The new
methods read this flag and return `{}` when disabled. No second flag invented.

### Error degradation set

`_execute` catches:
- `ThreadlinqsClientError` (incl. `ThreadlinqsSessionError`) — disabled / session failure
- `CircuitOpenError` — breaker open
- `RateLimitExceeded` — daily limit exhausted
- `asyncio.TimeoutError` — MCP call timeout
- `McpError` — SDK session errors (ConnectionClosedError subclass)

All yield `{}` — never an exception, never a fabricated result.

### File paths

- Implementation: `backend/app/services/threadlinqs_client.py`
- Tests: `backend/tests/unit/test_threadlinqs_client.py` (new, 26 tests)
- Test seam: mocked `_session` + `_initialized=True` + global breaker/limiter resets (same as test_m1)
