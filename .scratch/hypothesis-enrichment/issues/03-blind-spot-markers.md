# 03 — Blind-spot markers in expected_evidence_ru

**Type:** task
**Status:** resolved
**Blocked by:** None — can start immediately

**What to build:** An analyst-facing signal of *why* a Hypothesis is blind.
`expected_evidence_ru` gains a marker prefix derived from the Coverage status
of the blind spot, so the analyst instantly reads whether the gap is missing
rules, an invisible log source, partial fields, or missing Sysmon — instead of
re-deriving it from the rulebook. Expected evidence is built from MITRE data
sources × `fields.yaml` availability × `requires_gpo` × `adversary_playbooks`,
never from a hardcoded candidate-field list.

**Acceptance criteria:**

- [x] Four RU marker constants exist (R2-Q4), formatted `"{маркер} — {текст}"`:
      `COVERAGE_GAP` → «нет покрывающего правила», `DRL_BLIND` → «источник не
      видит событие», `FIELD_PARTIAL` → «частичное покрытие», `SYSMON_BLIND`
      → «Sysmon не охвачен»; the marker prefix is applied in
      `hypothesis_generator` (`_apply_blind_marker_ru`) when assembling
      `expected_evidence_ru`.
- [x] P1 marker-stream separation: `GAP_MARKER_RU` remains in `text_ru` and is
      also added to `expected_evidence_ru`; the other three markers appear
      **only** in `expected_evidence_ru`.
- [x] A COVERED hypothesis carries no blind-spot marker.
- [x] `expected_evidence_ru` is derived (data sources × availability ×
      `requires_gpo` × `adversary_playbooks`), not an expansion of a hardcoded
      candidate-field list.
- [x] Unit tests `tests/unit/test_hypothesis_generator.py` assert one case per
      marker (COVERAGE_GAP, DRL_BLIND, FIELD_PARTIAL, SYSMON_BLIND) and the
      absence of a marker for COVERED.

**Tests:** `tests/unit/test_hypothesis_generator.py`. Prior art: existing
generator tests over synthetic input (no MCP, no DB).

**ADDITIVE-ONLY:** constants + marker application appended; the M6.1
coverage/admiralty/priority path is untouched.

## Answer

Resolved in commit `…` (ticket 03).

Delivered:

- `app/services/management_service.py` — the four RU marker constants (R2-Q4
  exact glossary text, «never a synonym»): `DRL_BLIND_MARKER_RU`,
  `FIELD_PARTIAL_MARKER_RU`, `SYSMON_BLIND_MARKER_RU` plus
  `BLIND_MARKER_RU` mapping all four statuses; `COVERAGE_GAP` reuses the
  existing `GAP_MARKER_RU` (no duplicate of «нет покрывающего правила»).
- `app/services/hypothesis_generator.py` — `_apply_blind_marker_ru(status,
  text)` in one place; applied only where `expected_evidence_ru` is assembled
  in `generate_hypotheses`. Exact-key status contract (same as `_STATUS_RU`):
  `COVERED`, unknown, malformed, empty and `None` statuses pass through
  unmarked — the status set is never guessed. Idempotent: text already
  carrying its marker is returned unchanged. `text_ru` semantics untouched
  (P1: `GAP_MARKER_RU` stays there for `COVERAGE_GAP`; the other three
  markers never enter the narrative stream). Priority, ordering, Admiralty,
  coverage statuses and IDs untouched.
- `app/services/mitre_meta.py` — `expected_evidence_ru(technique_id,
  adversary_playbooks=())`: approved derivation over real typed inputs only
  — v15 fixture `data_sources` (offline, no MCP), `fields_catalog()` reading
  the real `backend/fixtures/fields.yaml` (per-field availability +
  `requires_gpo` flags from ticket 02), partial-availability and GPO notes
  surfaced in the evidence text, and an explicit provenance clause when data
  sources are absent or fields are not in the catalog. `adversary_playbooks`
  is a typed seam (empty default until ticket 08 feeds it); absence is
  reported as «не переданы — обогащение недоступно», never invented. The
  generator no longer reaches `_CANDIDATE_FIELDS` for expected evidence.
- `tests/unit/test_hypothesis_generator.py` — 15 new cases: exact marker
  constants (incl. `BLIND_MARKER_RU["COVERAGE_GAP"] is GAP_MARKER_RU`), one
  exact-prefix case per marker, no marker for `COVERED`, unknown/malformed
  status pass-through, idempotency, and generated-row stream separation
  (GAP marker in both `text_ru` and `expected_evidence_ru`; other markers
  only in `expected_evidence_ru`).

**Scope notes (documented):**

- `mitre_meta.gap_expected_evidence_ru` / `evidence_fields` (hardcoded
  `_CANDIDATE_FIELDS` based) are left in place — they still back the M6.3
  management summary's `_summary_evidence` mirror, which is outside ticket 03
  scope; the M6.4 generator path no longer uses them.
- `adversary_playbooks` live data arrives with ticket 08 (`threadlinqs_mcp_enricher`);
  ticket 03 keeps the seam offline/pure.

**Test evidence:** targeted `pytest -q tests/unit/test_hypothesis_generator.py
tests/unit/test_m6_meta.py -o addopts=""` → 38 passed. Full backend regression:
**992 passed, 11 skipped**, coverage 69.30% (`--cov-fail-under=60` gate
passes; lone-file runs cannot reach it — same note as tickets 01/02). `ruff
check` on all changed files → All checks passed.
