# 03 — Blind-spot markers in expected_evidence_ru

**Type:** task
**Status:** ready-for-agent
**Blocked by:** None — can start immediately

**What to build:** An analyst-facing signal of *why* a Hypothesis is blind.
`expected_evidence_ru` gains a marker prefix derived from the Coverage status
of the blind spot, so the analyst instantly reads whether the gap is missing
rules, an invisible log source, partial fields, or missing Sysmon — instead of
re-deriving it from the rulebook. Expected evidence is built from MITRE data
sources × `fields.yaml` availability × `requires_gpo` × `adversary_playbooks`,
never from a hardcoded candidate-field list.

**Acceptance criteria:**

- [ ] Four RU marker constants exist (R2-Q4), formatted `"{маркер} — {текст}"`:
      `COVERAGE_GAP` → «нет покрывающего правила», `DRL_BLIND` → «источник не
      видит событие», `FIELD_PARTIAL` → «частичное покрытие», `SYSMON_BLIND`
      → «Sysmon не охвачен»; the marker prefix is applied in
      `hypothesis_generator` (`_apply_blind_marker_ru`) when assembling
      `expected_evidence_ru`.
- [ ] P1 marker-stream separation: `GAP_MARKER_RU` remains in `text_ru` and is
      also added to `expected_evidence_ru`; the other three markers appear
      **only** in `expected_evidence_ru`.
- [ ] A COVERED hypothesis carries no blind-spot marker.
- [ ] `expected_evidence_ru` is derived (data sources × availability ×
      `requires_gpo` × `adversary_playbooks`), not an expansion of a hardcoded
      candidate-field list.
- [ ] Unit tests `tests/unit/test_hypothesis_generator.py` assert one case per
      marker (COVERAGE_GAP, DRL_BLIND, FIELD_PARTIAL, SYSMON_BLIND) and the
      absence of a marker for COVERED.

**Tests:** `tests/unit/test_hypothesis_generator.py`. Prior art: existing
generator tests over synthetic input (no MCP, no DB).

**ADDITIVE-ONLY:** constants + marker application appended; the M6.1
coverage/admiralty/priority path is untouched.
