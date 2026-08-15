# 06 — Threadlinqs client MCP methods

**Type:** task
**Status:** ready-for-agent
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
