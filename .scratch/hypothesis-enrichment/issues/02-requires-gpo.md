# 02 — requires_gpo field flag

**Type:** task
**Status:** ready-for-agent
**Blocked by:** None — can start immediately

**What to build:** Explicit per-field knowledge of which detection fields
depend on GPO configuration, so the analyst knows when a required telemetry
field is empty because of settings rather than absence of behavior. Adds
`requires_gpo` to every field in the field fixture and propagates it through
the fields parser into the field model.

**Acceptance criteria:**

- [ ] `backend/fixtures/fields.yaml` (the actual file on disk — not the
      documented typo `fileds.yaml`) carries `requires_gpo` on all 42 fields:
      `cmdline: true` (cited from `full_rules85.yaml:593,689,784,877,969,1139,1232,1305`
      and `shared_bbs.yaml:95-105` «Если GPO — пустое поле»), the other 41
      fields explicitly `false`.
- [ ] `fields_harvest` reads `requires_gpo` additively and propagates it into
      the field model (`requires_gpo: bool`); absent flag in legacy input
      defaults to `false` without error.
- [ ] Unit tests `tests/unit/test_fields_harvest.py` assert `cmdline → true`,
      other fields → `false`, and the default for a missing flag.

**Tests:** `tests/unit/test_fields_harvest.py`. Prior art: existing
`fields_harvest` parser tests (additive read path).

**ADDITIVE-ONLY:** appended lines in `backend/fixtures/fields.yaml` and the
parser; no existing field semantics change.
