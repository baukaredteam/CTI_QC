# 11 — Acceptance and smoke (GATE)

**Type:** task
**Status:** ready-for-human (smoke + regression + guardrail done; two live GATE
scan runs and e2e blocked on user review per PROJECT_STATUS STOP-for-review gate)
**Blocked by:** 01, 02, 05, 08, 09, 10

**What to build:** The end-to-end proof that the whole slice works in both MCP
modes. Runs the full regression, the smoke script against the four new MCP
tools on `TL-2026-1693`, and the GATE scan twice — `threadlinqs_enabled=True`
and `False` — checking contract 3.6 acceptance criteria and the cache-hit
behavior on the second run. No database involvement: Redis is down (cache off)
and `DB_PASS` is not provided, so e2e-vs-backend stays blocked.

**Acceptance criteria:**

- [x] Backend suite green: full regression **1181 passed, 11 skipped**,
      coverage 69.68% (gate `--cov-fail-under=60` passes); ruff clean on the
      changed files (`scripts/smoke_threadlinqs.py`,
      `tests/unit/test_smoke_guardrail.py`). Frontend untouched by this ticket
      (frontend state was already green, 58 passed, per ticket 10).
- [x] `scripts/smoke_threadlinqs.py` extended to exercise the four new MCP
      tools: `get_threat_hunting_bundle` (PASS, registered in v7.1.0),
      `predict_mitre_transitions`, `export_stix`, `get_attack_flow` — each
      returns its expected shape or the documented empty fallback (live run,
      exit 0).
- [ ] GATE scenario (a) `threadlinqs_enabled=True`: hypotheses carry
      populated `related_threats`, `adversary_playbooks`, `infrastructure_pivots`,
      and `predicted_next_techniques`; second run shows `tl:technique:*`
      cache hits (no repeat MCP calls for cached techniques). — BLOCKED: live
      feed scan is STOP-for-review gated in PROJECT_STATUS.
- [ ] GATE scenario (b) `threadlinqs_enabled=False`: the same hypotheses with
      MCP fields empty and no exception — pass-through behavior proven live.
      — BLOCKED: same gate.
- [ ] Contract 3.6 quality gate: for all v15 techniques in the GATE output,
      `technique_name` and `tactic` are non-empty; no placeholder names
      (`name == id`); markers present exactly by Coverage status; the 280
      hypothesis target is re-checked against the scan output. — BLOCKED:
      depends on the GATE scan output.
- [ ] e2e `hypotheses.spec` exercised after GATE (blocked items recorded as
      documented limitations, not failures). — BLOCKED: DB_PASS not provided.

**Tests:** full regression + extended smoke + two GATE runs. Prior art:
existing smoke script and GATE runbook from M6.3.

**ADDITIVE-ONLY:** smoke-script extensions and acceptance tests only; no
production code is touched by this ticket.

## Comments

### Evidence (2026-08-17) — agent-added acceptance test + live smoke

What was done, with proof:

1. **API-key leak fixed.** The script previously printed `api_key[:6]` as part
   of its startup banner; it now prints the inert marker `configured=true` and
   never the key or any prefix of it. Live run output confirms only
   `configured=true` appears between the server banner and the target list;
   exit code 0.
2. **Four-tool smoke section added (live-validated).** `main()` step 4 runs
   one `get_threat_hunting_bundle` + `get_attack_flow` + `export_stix` smoke
   per target bundle and one `predict_mitre_transitions` over the
   representative `_SMOKE_TECHNIQUE_IDS = ["T1027", "T1078", "T1003.002"]`
   (deterministic, quota-bounded). Live result against the real v7.1.0 server:
   - `get_threat_hunting_bundle` → **PASS** (registered tool; real envelope
     `{threat, iocs, detections, similar_threats, simulations,
     infrastructure_pivots, mitre_technique_ids, mitre_tactic_ids, ...}`);
   - `get_attack_flow` → **EMPTY_FALLBACK** (absent from the 54-tool registry)
     — honest, documented status, never faked;
   - `export_stix` → **NOT_AVAILABLE** (absent from the registry; consistent
     with the 06B NEEDS_DECISION — no contract invented);
   - `predict_mitre_transitions` → **EMPTY_FALLBACK** (absent from the
     registry) — honest status.
3. **`_process_bundle` switched to the verified tool call.** The bundle fetch
   previously called `get_threat_bundle` with a `get_threat` fallback chain —
   neither shape is in the v7.1.0 registry. It now calls
   `get_threat_hunting_bundle` with the ticket-06-verified `{threat_id}`-only
   schema; the fallback chain is dropped (a failed verified call prints the
   error and returns).
4. **Guardrail acceptance test added.** `backend/tests/unit/test_smoke_guardrail.py`
   (5 tests, following the `test_mitre_meta.py` source-guard convention):
   AST-based — no `print()` call may reference `api_key` in any form (no
   `api_key[:6]`, no f-string, no `%`-format); no `[:`-slice of the key
   anywhere; the configured path prints exactly `configured=true`; behavior —
   with no `THREADLINQS_API_KEY` in env or settings, `main()` prints the skip
   notice and exits 0 without connecting. 5/5 green; ruff clean.
5. **Full regression green.** `1181 passed, 11 skipped` (prior art baseline at
   slice start: 948; ticket 08 recorded 1139) — the smoke + guardrail changes
   regress nothing; coverage 69.68% passes the repo gate `--cov-fail-under=60`.

Remaining (blocked by design, not by code):

- The two **live GATE scan runs** (scenario a `threadlinqs_enabled=True`,
  scenario b `threadlinqs_enabled=False`) and the **contract 3.6 quality gate**
  need the first live feed scan, which PROJECT_STATUS explicitly gates:
  "run the first live feed scan ONLY after user review of this slice
  (objective: STOP for review first)".
- **e2e `hypotheses.spec`** stays blocked: `DB_PASS` is a local placeholder
  only (per PROJECT_STATUS env facts), so e2e-vs-backend is not runnable here;
  recorded as documented limitation, not failure.
