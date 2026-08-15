# 07 — Normalizer extraction blocks

**Type:** task
**Status:** ready-for-agent
**Blocked by:** None — can start immediately

**What to build:** Three additive extraction blocks in the Threadlinqs
normalizer so raw bundle responses become the enrichment fields the pipeline
consumes: adversary playbooks, infrastructure pivots, and related threats.
The existing indicator and technique extraction paths are untouched.

**Acceptance criteria:**

- [ ] The normalizer gains, additively:
      - `_extract_simulations` → `adversary_playbooks: list[str]` (enriches
        `expected_evidence_ru` in ticket 08);
      - `_extract_pivots` → `infrastructure_pivots: list[dict]` (supplements
        IOCs, never replaces them);
      - `_extract_similar_threats` → `related_threats: list[str]`.
- [ ] Empty or malformed input yields empty lists, never an exception.
- [ ] `_extract_indicators` / `_extract_techniques` are not modified
      (ADDITIVE-ONLY).
- [ ] Unit tests `tests/unit/test_threadlinqs_normalizer.py` assert each block
      on a representative bundle fixture and the empty-input behavior.

**Tests:** `tests/unit/test_threadlinqs_normalizer.py`. Prior art: existing
normalizer tests over bundle fixtures.

**ADDITIVE-ONLY:** appended functions only; the working normalizer logic is
not rewritten.
