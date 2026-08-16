# 07 — Normalizer extraction blocks

**Type:** task
**Status:** resolved
**Blocked by:** None — can start immediately

**What to build:** Three additive extraction blocks in the Threadlinqs
normalizer so raw bundle responses become the enrichment fields the pipeline
consumes: adversary playbooks, infrastructure pivots, and related threats.
The existing indicator and technique extraction paths are untouched.

**Acceptance criteria:**

- [x] The normalizer gains, additively:
      - `_extract_simulations` → `adversary_playbooks: list[str]` (enriches
        `expected_evidence_ru` in ticket 08);
      - `_extract_pivots` → `infrastructure_pivots: list[dict]` (supplements
        IOCs, never replaces them);
      - `_extract_similar_threats` → `related_threats: list[str]`.
- [x] Empty or malformed input yields empty lists, never an exception.
- [x] `_extract_indicators` / `_extract_techniques` are not modified
      (ADDITIVE-ONLY).
- [x] Unit tests `tests/unit/test_threadlinqs_normalizer.py` assert each block
      on a representative bundle fixture and the empty-input behavior.

**Tests:** `tests/unit/test_threadlinqs_normalizer.py`. Prior art: existing
normalizer tests over bundle fixtures.

**ADDITIVE-ONLY:** appended functions only; the working normalizer logic is
not rewritten.

## Answer

Ticket 07 is complete.

- Three pure extraction blocks appended to `threadlinqs_normalizer.py`, each
  consuming the raw payload for one envelope key:
  - `_extract_simulations(payload)` → `adversary_playbooks` — str items kept
    trimmed, dict items read by prefix-key priority
    `("playbook", "name", "title", "value")`; unknown-key dicts skipped.
  - `_extract_similar_threats(payload)` → `related_threats` — same shape with
    `("name", "title", "value", "id")`.
  - `_extract_pivots(payload)` → `infrastructure_pivots` — scalar-only
    dicts (str trimmed / int / float / bool kept, nested dict/list/None
    dropped, empty results excluded), deduped by canonical sorted-key JSON
    fingerprint, first occurrence wins.
  - Shared `_extract_text_items` helper does the str/dict walk + trim +
    `dict.fromkeys` dedupe (preserve order) for both list[str] blocks.
- Contract: missing/None/wrong-type/empty input → `[]`, never raises; values
  are never evaluated or executed (pinned by a test feeding
  command-injection-encoded strings and a Python `__import__('os')` payload as
  plain text — extracted verbatim, not run).
- Wiring: `normalize_bundle` reads the three top-level envelope keys with the
  existing `data`-fallback convention and passes them into the
  `NormalizedThreat(...)` constructor keywords. Three fields appended to the
  dataclass (`adversary_playbooks`, `infrastructure_pivots`,
  `related_threats`, all `default_factory=list`) — the only constructor call
  site uses keyword args, so the append is byte-compatible; no positional
  construction anywhere in `app/` or `tests/`.
- ADDITIVE-ONLY verified by diff: new `import json`, 3 fields, 4 functions,
  and wiring; `_extract_indicators` / `_extract_techniques` untouched. Pivots
  supplement IOCs — a domain present as both an IOC and a pivot stays in both
  lists (pinned test), never replaced.
- Evidence: red phase 21 failed / 2 passed (assertion-level, missing symbols);
  targeted **23/23 green**, existing Threadlinqs suites **72/72 green**; full
  backend regression **1113 passed, 11 skipped**, coverage 69.48% (gate
  `--cov-fail-under=60` passes on the full run); `ruff check` clean on the
  changed file (`ruff format` drift on pre-existing lines only — HEAD fails
  format-check identically; CI gates on `ruff check .`).
