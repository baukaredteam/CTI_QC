# 02 — requires_gpo field flag

**Type:** task
**Status:** resolved
**Blocked by:** None — can start immediately

**What to build:** Explicit per-field knowledge of which detection fields
depend on GPO configuration, so the analyst knows when a required telemetry
field is empty because of settings rather than absence of behavior. Adds
`requires_gpo` to every field in the field fixture and propagates it through
the fields parser into the field model.

**Acceptance criteria:**

- [x] `backend/fixtures/fields.yaml` (the actual file on disk — not the
      documented typo `fileds.yaml`) carries `requires_gpo` on all 42 fields:
      `cmdline: true` (cited from `full_rules85.yaml:593,689,784,877,969,1139,1232,1305`
      and `shared_bbs.yaml:95-105` «Если GPO — пустое поле»), the other 41
      fields explicitly `false`.
- [x] `fields_harvest` reads `requires_gpo` additively and propagates it into
      the field model (`requires_gpo: bool`); absent flag in legacy input
      defaults to `false` without error.
- [x] Unit tests `tests/unit/test_fields_harvest.py` assert `cmdline → true`,
      other fields → `false`, and the default for a missing flag.

**Tests:** `tests/unit/test_fields_harvest.py`. Prior art: existing
`fields_harvest` parser tests (additive read path).

**ADDITIVE-ONLY:** appended lines in `backend/fixtures/fields.yaml` and the
parser; no existing field semantics change.

## Answer

Resolved in commit `…` (ticket 02, push `cti_qc/main`).

Delivered:

- `backend/fixtures/fields.yaml` — every entry (all **54** entries on disk,
  not the ticket's documented count of 42; the file has drifted since
  `metadata.total_fields: 42` was written) now carries an explicit
  `requires_gpo`. Only `cmdline: true`; the other 53 entries explicitly
  `false`. The 54 → 49 unique-name delta exists because a few names appear
  under multiple log sources (`proc_file_path` ×3, `event_description` ×2,
  `task_name` ×2, `proc_usr_sid` ×2); every entry got the flag regardless.
- `app/schemas/rules.py` — `CustomField.requires_gpo: bool = False` appended
  (additive; legacy input without the key parses with the default).
- `app/services/fields_harvest.py` — `HarvestedField.requires_gpo: bool =
  False` appended; both readers (`harvest_fields_from_rules`,
  `harvest_fields_from_fields_file`) set `hf.requires_gpo = True` when
  `cf.requires_gpo`; `merge_harvests` OR-combines the flag (copy on create,
  OR on update). No existing field semantics touched.
- `tests/unit/test_fields_harvest.py` — 9 tests: raw fixture has an explicit
  flag on every entry, `cmdline` is the only `true`, every other entry
  explicitly `false`, harvest propagation (`cmdline → true`, others → false),
  bool survives `strip_yaml_values` (Pydantic sees a real bool, not the string
  `"true"`), and legacy input with no flag defaults to `false` at both schema
  and harvest level.

**Count deviation (documented):** the acceptance text says "42 fields / other
41 false", but the committed fixture on disk holds 54 entries (49 unique
names). Tests assert on the real file, so they cover all 54 entries — the
ticket's count was a stale `total_fields: 42` figure. `metadata.total_fields`
was left untouched (ADDITIVE-ONLY: no existing field semantics change).

**Test evidence:** `pytest tests/unit/test_fields_harvest.py` → 9 passed.
Full regression: `pytest` (backend, all suites) → **977 passed, 11 skipped**,
total coverage 69.25% (the `--cov-fail-under=60` gate passes on the full
run; a lone-file run cannot reach the gate — same note as ticket 01).
