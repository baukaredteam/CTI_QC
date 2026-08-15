# 05 — Chokepoint candidates by template × fields.yaml intersection

**Type:** task
**Status:** resolved
**Blocked by:** None — can start immediately

**What to build:** Chokepoint candidates derived from catalog data, not from
covering rules. A technique is a candidate chokepoint when its telemetry
fields (mitre_meta templates) intersect fields.yaml records that carry
`adversary_control: LOW`. This must work even for COVERAGE_GAP hypotheses,
where no covering rules exist at all. Rule-derived LOW fields keep living in
the existing `chokepoints` field (`_chokepoints_for`) — untouched.

**Acceptance criteria:**

- [x] `candidate_chokepoints(technique_id)` in `hypothesis_generator` computes
      the canonical intersection: телеметрические поля техники (шаблоны
      mitre_meta) ∩ записи `fields.yaml` с `adversary_control: LOW`.
- [x] It does not depend on covering rules: for a COVERAGE_GAP hypothesis
      (`covering_rule_ids == []`) the candidates are non-empty whenever the
      technique's template contains a LOW field.
- [x] Fields with `adversary_control: HIGH` (or not LOW) in the template never
      appear in the candidates.
- [x] The existing `chokepoints` field (`_chokepoints_for`, rule-derived LOW)
      is not modified.
- [x] Unit tests `tests/unit/test_hypothesis_generator.py` assert:

      (1) a LOW field present in the fields catalog and in the technique
          template → the field is in the candidates;
      (2) a HIGH field → not in the candidates;
      (3) GAP hypothesis (`covering_rule_ids == []`) → candidates non-empty
          for a technique whose template holds a LOW field.

**Tests:** `tests/unit/test_hypothesis_generator.py`. Prior art: existing
generator tests over synthetic input.

**ADDITIVE-ONLY:** the candidate lookup is added to the generator; the M6.1
coverage/admiralty/priority path and `_chokepoints_for` are untouched.

## Answer

Ticket 05 is complete.

- Source of truth: the generator path now reads the real `fields.yaml`
  catalog instead of the hardcoded `_CANDIDATE_FIELDS` frozenset.
  `mitre_meta.parse_fields_catalog(data)` is the new pure, deterministic
  parse step (duplicates merge: availabilities union, `requires_gpo`
  OR-combined, adversary controls union per name, first non-empty note
  wins); `fields_catalog()` keeps its exact signature and degradation while
  delegating to it. Entries now carry `adversary_controls` (set of
  canonicalized controls) and `notes`.
- Canonical intersection: `_telemetry_fields(technique_id)` ∩ catalog names
  where `adversary_controls == {"LOW"}` — every entry for a duplicated name
  must declare LOW; a contradictory duplicate (`LOW` + `HIGH`) is excluded
  (an ambiguous control is never exact LOW). Exact comparison follows the
  project's existing strip+upper normalization (coverage analyzer, fields
  harvest); unknown/missing catalog entries never qualify.
- Semantics correction (honest deviation from prior candidate behavior): the
  old `candidate_fields` path included HIGH-control fields because
  `_CANDIDATE_FIELDS` was a hardcoded semantic-field list, not a control
  filter. `mitre_meta.candidate_fields` and the M6.3 summary
  (`management_service._candidate_chokepoints`) keep their existing
  semantics unchanged — only the hypothesis-generator path swapped to the
  canonical intersection, per the ticket boundary.
- No new Hypothesis schema fields: `HypothesisChokepoint` (field + note_ru)
  carries the candidate metadata; catalog notes flow into `note_ru`, with a
  deterministic Russian fallback when the note is absent.
- GAP proof: technique `T1613` is present in no rule and no fixture → the
  analyzer emits a `COVERAGE_GAP` row with `covering_rule_ids == []`; the
  fallback template `("proc_cmdline", "dns_rname")` ∩ LOW catalog yields
  `{"dns_rname"}` → non-empty candidates without covering rules (pinned by
  a dedicated test).
- Rule-derived `chokepoints` untouched: `_chokepoints_for` still scans rule
  `custom_fields` only; a test asserts empty for any technique with zero
  covering rules and byte-identity against generator output.
- Evidence: 17 new tests (red phase 8 assertion-level failures before the
  implementation; targeted 76/76 green with `addopts=""` incl.
  `test_m6_meta.py`); full backend regression **1030 passed, 11 skipped**,
  coverage 69.33% (gate `--cov-fail-under=60` passes on the full run);
  ruff clean on changed files.
