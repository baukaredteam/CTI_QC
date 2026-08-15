# 10 — Frontend hypotheses page

**Type:** task
**Status:** ready-for-agent
**Blocked by:** 03, 04, 08, 09

**What to build:** The analyst-facing rendering of the new Hypothesis fields on
the Hypotheses page: the confidence-priority bonus badge, blind-spot marker
prefixes inside «Ожидаемые свидетельства», related threats, and the predicted
next techniques that carry the `attack_flow` basis. Display-only — no new
mutations, no new permissions.

**Acceptance criteria:**

- [ ] `frontend/src/types/hypothesis.ts` mirrors the four new backend fields:
      `confidence_priority_bonus`, `related_threats`, `adversary_playbooks`
      (display), `predicted_next_techniques`.
- [ ] `frontend/src/pages/Hypotheses.tsx` renders:
      - a bonus badge on the Hypothesis card when `actor_confidence` is
        `high` and `confidence_priority_bonus` is non-null (P2: display-only,
        base priority unchanged);
      - the blind-spot marker prefix in «Ожидаемые свидетельства» as returned
        by the backend (COVERAGE_GAP / DRL_BLIND / FIELD_PARTIAL / SYSMON_BLIND);
      - `related_threats` list;
      - `predicted_next_techniques` filtered to `basis: 'attack_flow'` only.
- [ ] Empty/absent new fields render as nothing (no placeholders, no errors).
- [ ] Frontend build and lint pass; TypeScript types match the backend shape.

**Tests:** frontend build + lint (existing precedent: the analyzer page has no
covering frontend tests); backend shape verified through ticket 11's
acceptance + smoke run.

**ADDITIVE-ONLY:** appended type fields and card sections; no existing
Hypothesis card behavior or styling is rewritten.
