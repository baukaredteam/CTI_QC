# 06B — export_stix typed wrapper (deferred)

**Type:** task
**Status:** NEEDS_DECISION (blocked — inherited from issue 06)
**Blocked by:** 06 (partially-implemented)

**What to build (when unblocked):** `ThreadlinqsClient.export_stix(...)` — the
typed read-only wrapper that ticket 06's original checklist listed as the
canonical STIX source for the fixture generator (ticket 01, P4). Signature as
originally specified: `export_stix(threat_id=None, actor=None, cve_id=None,
include_osint=False)` — but see "No invented contract" below.

## Why this ticket is BLOCKED / NEEDS_DECISION

Verified against the authoritative `intelthreadlinqs-mcp@7.1.0` tool registry
(`dist/index.js` installed globally via npm, protocol reconciliation in issue
06):

- **No `export_stix` tool exists** in the v7.1.0 MCP tool list (54 tools
  enumerated, Purple tier). The server source itself says: "STIX export could
  be a roadmap ask (the roadmap mentions it)."
- Therefore there is **no proven tool name / inputSchema / result envelope** to
  code against. The user's standing gate applies: «Если real tool list/schema
  недоступны, не выдумывай контракт.» A stub, a fake result, a roadmap-based
  wrapper, or an invented schema would violate that gate.

## Unblock conditions (any one)

1. **Tool appears in the real MCP tool list** — `export_stix` (or an equivalent
   STIX export tool under a different name) is present in the
   `intelthreadlinqs-mcp` registry the deployment actually runs, with an
   observable `inputSchema`; OR
2. **Owner provides an official schema contract** — an explicit tool
   name + inputSchema + result-envelope contract for STIX export, submitted by
   the tool owner (matching the verification method used for the three accepted
   methods in issue 06).

Until one of these holds: **no implementation**. The dependent work is already
covered by the committed offline fixture (see the map.md decision record).

## Required tests after unblock (both conditions)

When either unblock condition holds, the wrapper must land with:

- **success-shape test** — mocked transport returns the documented result
  envelope; assert the exact key set / shape, non-secret fields only;
- **fallback test** — `threadlinqs_enabled=False`, breaker open, timeout, rate
  limit, session loss each return the method's empty default (`{}`), never an
  exception (same degradation set as the three accepted methods);
- **secret-leak test** — the API key never re-emitted in the return value or a
  raise (same pattern as `test_no_api_key_leak_on_timeout[*]` in ticket 06).

Tests of the live export must **never** run in CI (quota/flakiness — same rule
as ticket 01 F2: the live export is manual-generation-only).

## No-original-contract note

The four-argument signature above is the ticket-06 plan-level shape, NOT a
verified schema. It must be reconciled against the real tool schema at
implementation time; argument names and envelope may differ. If the tool lands
with no documented result key set, `_parse_tool_result` still guards the shape
(the wrapper returns `{}` on malformed/non-dict payloads).

**ADDITIVE-ONLY:** when implemented, appends a method to
`backend/app/services/threadlinqs_client.py`; existing client logic is not
rewritten, and the other three Ticket 06 methods are untouched.

---

## Comments

- 2026-08-16 — Created as a separate tracker issue to close the boundary of
  Ticket 06: the three verified methods are accepted independently; the
  `export_stix` checklist item is deferred with an explicit NEEDS_DECISION
  status and verifiable unblock conditions. Production code, tests, schemas and
  MCP configuration were NOT touched by this ticket (boundary-only bookkeeping).
  Inherited NEEDS_DECISION recorded from the `.omo` run-continuation signal;
  the session file itself was neither read nor modified.