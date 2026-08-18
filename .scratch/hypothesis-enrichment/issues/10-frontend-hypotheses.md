# 10 — Frontend hypotheses page

**Type:** task
**Status:** resolved (display-only enrichment rendering)
**Blocked by:** 03, 04, 08, 09

**What to build:** The analyst-facing rendering of the new Hypothesis fields on
the Hypotheses page: the confidence-priority bonus badge, blind-spot marker
prefixes inside «Ожидаемые свидетельства», related threats, and the predicted
next techniques that carry the `attack_flow` basis. Display-only — no new
mutations, no new permissions.

**Acceptance criteria:**

- [x] `frontend/src/api/client.ts` (note: there is no `frontend/src/types/hypothesis.ts`; the
      Hypothesis interface lives in the API client) mirrors the new backend fields:
      `confidence_priority_bonus`, `related_threats`, `adversary_playbooks`
      (display), `infrastructure_pivots`, `predicted_next_techniques`.
- [x] `frontend/src/pages/Hypotheses.tsx` renders:
      - a bonus badge on the Hypothesis card when `confidence_priority_bonus`
        is non-null (reconciled: `actor_confidence` is NOT a stored response
        field; the badge is driven by `confidence_priority_bonus` only.
        P2: display-only, base priority unchanged);
      - the blind-spot marker prefix in «Ожидаемые свидетельства» as returned
        by the backend (COVERAGE_GAP / DRL_BLIND / FIELD_PARTIAL / SYSMON_BLIND) —
        existing passthrough, verified unchanged;
      - `related_threats` list;
      - `adversary_playbooks` list;
      - `infrastructure_pivots` (safe scalar key:value pairs only);
      - `predicted_next_techniques` filtered to `basis: 'attack_flow'` only.
- [x] Empty/absent new fields render as nothing (no placeholders, no errors;
      legacy row without the new keys renders cleanly, proven by e2e fixture).
- [x] Frontend build and lint pass; TypeScript types match the backend shape.

**Tests:** frontend build + lint passed; e2e coverage added in
`frontend/tests/e2e/hypotheses.spec.ts` (enriched / bonus-null / legacy rows);
PATCH + filter regressions stay green. Backend shape verified through the same
contract the backend schema already guarantees; ticket 11's acceptance + smoke
run remains out of scope for this ticket.

**ADDITIVE-ONLY:** appended type fields and card sections; no existing
Hypothesis card behavior or styling is rewritten.

## Resolution

**Chosen: display-only additive rendering** implemented after preflight
(ticket read, repo facts, codegraph shape authority, skill load).

Changes (all additive, no behavior change for existing paths):

- `frontend/src/api/client.ts`: `Hypothesis` interface extended with
  `confidence_priority_bonus: number | null`, `related_threats: string[]`,
  `adversary_playbooks: string[]`,
  `infrastructure_pivots: Array<Record<string, unknown>>`,
  `predicted_next_techniques: Array<{technique_id, name, probability, basis}>`.
- `frontend/src/pages/Hypotheses.tsx`: bonus badge next to the unchanged base
  priority (renders only when `confidence_priority_bonus` is a number);
  sections for related threats, adversary playbooks, infrastructure pivots
  (scalar-only via `scalarEntries`, nested objects/arrays dropped — no
  `[object Object]`), and predicted next techniques (attack_flow filter,
  finite-number probability guard, muted `[attack_flow]` provenance).
- `frontend/tests/e2e/support/mock-api.ts`: fixtures extended — h-1 enriched
  (with nested-object + array pivot and canonical-basis prediction cases),
  h-2 bonus-null (rejected, sections render without badge), h-3 legacy (no new
  keys at all; proves `?? []` normalization).
- `frontend/tests/e2e/hypotheses.spec.ts`: new test asserting badge visibility
  (once, on h-1 only), section content, absence on legacy row, canonical
  hidden, `[object Object]` never rendered; existing PATCH/filter tests green.

## Evidence

- Frontend lint: clean (`eslint src --ext ts,tsx --max-warnings 0`).
- Frontend build: `tsc && vite build` exit 0 (only pre-existing
  >500 kB chunk-size warning, unrelated).
- Playwright e2e `hypotheses.spec.ts`: **4 passed** (incl. new enrichment
  test) against the built preview with mock API.
- Visual smoke screenshot captured at
  `frontend/test-results/ticket10-visual-smoke.png` (fixture/mock-only, local).
- OCR delegate review: 4/4 changed files reviewed; 1 low finding (EOF newline,
  now fixed); `.omo/run-continuation/*` session files skipped (not part of the
  change, must never be staged).
- Diff tree: 5 files (this ticket + 4 frontend files, +190/−5 incl. the
  newline normalization), additive-only.

## Comments

- Created 2026-08-16 as Ticket 10 in the hypothesis-enrichment tracker.
- Resolved 2026-08-17: implemented after 09B (`f222005`) was committed and
  pushed. Actor-confidence reconciliation applied: badge driven solely by
  `confidence_priority_bonus !== null`; no frontend confidence computation,
  no sorting, no new route, no permissions, no mutations.
- Full acceptance GATE + docs/handoff remain Tickets 11 and 12 — not started.
