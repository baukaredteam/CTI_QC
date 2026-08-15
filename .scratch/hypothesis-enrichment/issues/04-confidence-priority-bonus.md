# 04 — Confidence priority bonus

**Type:** task
**Status:** resolved
**Blocked by:** None — can start immediately

**What to build:** A display-only 1.25 priority bonus for high-confidence
actors. When a Hypothesis comes from a source with `actor_confidence == "high"`,
its card shows the bonus value next to the base priority, so the analyst sees
the boosted confidence without the underlying priority being changed or the
queue reordered.

**Acceptance criteria:**

- [x] The Hypothesis schema in `app/schemas/hypothesis.py` gains
      `confidence_priority_bonus: float | None = None` (optional, default
      `None` — no migration).
- [x] `generate_hypotheses` computes it as `priority × 1.25` when
      `actor_confidence == "high"`, else `None`.
- [x] The existing `priority` value is never mutated (P2); the M6.1
      `analyze_coverage` ordering is unaffected — the bonus is display-only.
- [x] Unit tests `tests/unit/test_hypothesis_generator.py` assert
      `bonus == priority × 1.25` for high and `None` otherwise, plus that the
      original `priority` is unchanged in both cases.

**Tests:** `tests/unit/test_hypothesis_generator.py`. Prior art: existing
generator tests over synthetic input.

**ADDITIVE-ONLY:** one schema field + one computed field; no existing field or
ordering logic changes.

**Serialization note:** this is the first of three tickets appending fields to
the Hypothesis schema (04 → 08 → 09). Land in this order to avoid conflicting
appends.

## Answer

Ticket 04 is complete.

- Schema: `backend/app/schemas/hypothesis.py` gains
  `confidence_priority_bonus: float | None = Field(default=None)` as the last
  schema field — pure append, no migration, no other field touched. Absent
  keys in stored JSON read as `None` (`model_validate` backward compatible;
  pinned by a round-trip test that drops the key).
- Computation: `generate_hypotheses` computes
  `float(rec.priority) * 1.25 if actor_confidence_high else None` per row.
  `actor_confidence_high` reuses the project's existing canonical predicate
  (`hypothesis_generator._evidence` / `management_service._evidence`):
  `str(confidence).lower() in {"high", "высокая"}` — no new synonyms or
  taxonomy introduced. `medium`, `low`, empty, `unknown` and `community` are
  all `None`.
- Canonical normalization note (honest deviation from ticket text): the
  normalizer's `_extract_attribution` applies `.strip()` as part of the
  existing canonical normalization, so a raw `"HIGH "` attribution value
  reads as canonical `high` and earns the bonus. No new normalization was
  added; the test encodes this existing behavior explicitly.
- Display-only pinned by tests: `priority` identical with and without the
  bonus; hypothesis ids and queue order unchanged (priorities remain
  descending, same as `analyze_coverage` blind-spot ordering); bonus does not
  enter scoring, sorting, validation, rejection, or persistence decisions
  (status transition preserves the bonus value without affecting it).
- Evidence: 21 new tests (red phase: 19 assertion-level failures before the
  implementation; targeted 51/51 green with `addopts=""`); full backend
  regression 1013 passed, 11 skipped, coverage 69.30% (gate
  `--cov-fail-under=60` passes on the full run); ruff clean on changed files.
