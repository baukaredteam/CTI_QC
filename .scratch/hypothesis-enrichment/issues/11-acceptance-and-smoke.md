# 11 — Acceptance and smoke (GATE)

**Type:** task
**Status:** ready-for-agent
**Blocked by:** 01, 02, 05, 08, 09, 10

**What to build:** The end-to-end proof that the whole slice works in both MCP
modes. Runs the full regression, the smoke script against the four new MCP
tools on `TL-2026-1693`, and the GATE scan twice — `threadlinqs_enabled=True`
and `False` — checking contract 3.6 acceptance criteria and the cache-hit
behavior on the second run. No database involvement: Redis is down (cache off)
and `DB_PASS` is not provided, so e2e-vs-backend stays blocked.

**Acceptance criteria:**

- [ ] Backend suite green (baseline at slice start: 948 passed, 11 skipped)
      plus the new unit tests; frontend 58 plus new tests; ruff clean; frontend
      build + lint pass.
- [ ] `scripts/smoke_threadlinqs.py` extended to exercise the four new MCP
      tools on `TL-2026-1693`: `get_threat_hunting_bundle`,
      `predict_mitre_transitions`, `export_stix`, `get_attack_flow` — each
      returns its expected shape or the documented empty fallback.
- [ ] GATE scenario (a) `threadlinqs_enabled=True`: hypotheses carry
      populated `related_threats`, `adversary_playbooks`, `infrastructure_pivots`,
      and `predicted_next_techniques`; second run shows `tl:technique:*`
      cache hits (no repeat MCP calls for cached techniques).
- [ ] GATE scenario (b) `threadlinqs_enabled=False`: the same hypotheses with
      MCP fields empty and no exception — pass-through behavior proven live.
- [ ] Contract 3.6 quality gate: for all v15 techniques in the GATE output,
      `technique_name` and `tactic` are non-empty; no placeholder names
      (`name == id`); markers present exactly by Coverage status; the 280
      hypothesis target is re-checked against the scan output.
- [ ] e2e `hypotheses.spec` exercised after GATE (blocked items recorded as
      documented limitations, not failures).

**Tests:** full regression + extended smoke + two GATE runs. Prior art:
existing smoke script and GATE runbook from M6.3.

**ADDITIVE-ONLY:** smoke-script extensions and acceptance tests only; no
production code is touched by this ticket.
