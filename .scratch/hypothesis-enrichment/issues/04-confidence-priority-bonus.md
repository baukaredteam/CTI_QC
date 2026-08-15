# 04 — Confidence priority bonus

**Type:** task
**Status:** ready-for-agent
**Blocked by:** None — can start immediately

**What to build:** A display-only 1.25 priority bonus for high-confidence
actors. When a Hypothesis comes from a source with `actor_confidence == "high"`,
its card shows the bonus value next to the base priority, so the analyst sees
the boosted confidence without the underlying priority being changed or the
queue reordered.

**Acceptance criteria:**

- [ ] The Hypothesis schema in `app/schemas/hypothesis.py` gains
      `confidence_priority_bonus: float | None = None` (optional, default
      `None` — no migration).
- [ ] `generate_hypotheses` computes it as `priority × 1.25` when
      `actor_confidence == "high"`, else `None`.
- [ ] The existing `priority` value is never mutated (P2); the M6.1
      `analyze_coverage` ordering is unaffected — the bonus is display-only.
- [ ] Unit tests `tests/unit/test_hypothesis_generator.py` assert
      `bonus == priority × 1.25` for high and `None` otherwise, plus that the
      original `priority` is unchanged in both cases.

**Tests:** `tests/unit/test_hypothesis_generator.py`. Prior art: existing
generator tests over synthetic input.

**ADDITIVE-ONLY:** one schema field + one computed field; no existing field or
ordering logic changes.

**Serialization note:** this is the first of three tickets appending fields to
the Hypothesis schema (04 → 08 → 09). Land in this order to avoid conflicting
appends.
