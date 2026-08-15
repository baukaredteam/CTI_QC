# 05 — Chokepoint candidates by template × fields.yaml intersection

**Type:** task
**Status:** ready-for-agent
**Blocked by:** None — can start immediately

**What to build:** Chokepoint candidates derived from catalog data, not from
covering rules. A technique is a candidate chokepoint when its telemetry
fields (mitre_meta templates) intersect fields.yaml records that carry
`adversary_control: LOW`. This must work even for COVERAGE_GAP hypotheses,
where no covering rules exist at all. Rule-derived LOW fields keep living in
the existing `chokepoints` field (`_chokepoints_for`) — untouched.

**Acceptance criteria:**

- [ ] `candidate_chokepoints(technique_id)` in `hypothesis_generator` computes
      the canonical intersection: телеметрические поля техники (шаблоны
      mitre_meta) ∩ записи `fields.yaml` с `adversary_control: LOW`.
- [ ] It does not depend on covering rules: for a COVERAGE_GAP hypothesis
      (`covering_rule_ids == []`) the candidates are non-empty whenever the
      technique's template contains a LOW field.
- [ ] Fields with `adversary_control: HIGH` (or not LOW) in the template never
      appear in the candidates.
- [ ] The existing `chokepoints` field (`_chokepoints_for`, rule-derived LOW)
      is not modified.
- [ ] Unit tests `tests/unit/test_hypothesis_generator.py` assert:

      (1) a LOW field present in the fields catalog and in the technique
          template → the field is in the candidates;
      (2) a HIGH field → not in the candidates;
      (3) GAP hypothesis (`covering_rule_ids == []`) → candidates non-empty
          for a technique whose template holds a LOW field.

**Tests:** `tests/unit/test_hypothesis_generator.py`. Prior art: existing
generator tests over synthetic input.

**ADDITIVE-ONLY:** the candidate lookup is added to the generator; the M6.1
coverage/admiralty/priority path and `_chokepoints_for` are untouched.