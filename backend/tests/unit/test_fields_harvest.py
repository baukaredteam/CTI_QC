"""Ticket 02 test suite — requires_gpo field flag.

Covers (ticket ``.scratch/hypothesis-enrichment/issues/02-requires-gpo.md``,
ADDITIVE-ONLY):

1. Every field in the real ``backend/fixtures/fields.yaml`` carries an explicit
   ``requires_gpo`` bool; ``cmdline: true`` (GPO "Include command line in
   process creation events" — cited at ``full_rules85.yaml:593,689,784,877,
   969,1139,1232,1305`` and ``shared_bbs.yaml:95-105``), every other field an
   explicit ``false``.
2. ``fields_harvest`` reads the flag additively and propagates it into the
   field model (``HarvestedField.requires_gpo: bool``).
3. An absent flag in legacy input defaults to ``False`` without error (both
   schema- and harvest-level).
"""

from __future__ import annotations

from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent.parent          # backend/tests
BACKEND_DIR = TESTS_DIR.parent                              # backend/
REAL_FIELDS = BACKEND_DIR / "fixtures" / "fields.yaml"

# The only field whose content depends on GPO configuration — the command line
# of 4688 process-creation events (audit policy "Include command line").
GPO_FIELD = "cmdline"


def _raw_yaml() -> dict:
    """Byte-faithful YAML load of the committed fields fixture."""
    import yaml

    with REAL_FIELDS.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, dict), "fields.yaml did not parse as a dict"
    return data


# ---------------------------------------------------------------------------
# 1. Real fixture carries an explicit requires_gpo on every field
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not REAL_FIELDS.exists(),
    reason="Real fixture fields.yaml not present",
)
class TestFieldsFixtureRequiresGpo:
    def test_every_entry_has_explicit_requires_gpo(self):
        entries = _raw_yaml()["custom_fields"]
        assert entries, "fields.yaml has no custom_fields"
        missing = [e["name"] for e in entries if "requires_gpo" not in e]
        assert not missing, f"entries without requires_gpo: {missing}"

    def test_cmdline_is_the_only_true(self):
        entries = _raw_yaml()["custom_fields"]
        flagged = [
            e["name"] for e in entries
            if e.get("requires_gpo") is True
        ]
        assert flagged == [GPO_FIELD], f"unexpected requires_gpo=true: {flagged}"

    def test_every_other_field_explicitly_false(self):
        entries = _raw_yaml()["custom_fields"]
        for entry in entries:
            if entry["name"] == GPO_FIELD:
                continue
            assert entry["requires_gpo"] is False, entry["name"]


# ---------------------------------------------------------------------------
# 2. fields_harvest propagates requires_gpo into the field model
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not REAL_FIELDS.exists(),
    reason="Real fixture fields.yaml not present",
)
class TestHarvestPropagatesRequiresGpo:
    @pytest.fixture(scope="class")
    @classmethod
    def harvest(cls):
        from app.services.rules_parser import parse_fields_file
        from app.services.fields_harvest import harvest_fields_from_fields_file

        ff = parse_fields_file(REAL_FIELDS)
        return harvest_fields_from_fields_file(ff)

    def test_cmdline_requires_gpo_true(self, harvest):
        assert harvest[GPO_FIELD].requires_gpo is True

    def test_other_fields_requires_gpo_false(self, harvest):
        others = [name for name in harvest if name != GPO_FIELD]
        assert others, "harvest has only cmdline? unexpected"
        for name in others:
            assert harvest[name].requires_gpo is False, name

    def test_requires_gpo_survives_strip_and_pydantic(self, harvest):
        # strip_yaml_values must keep it a real bool (not "true"/"false")
        for hf in harvest.values():
            assert isinstance(hf.requires_gpo, bool), hf.name


# ---------------------------------------------------------------------------
# 3. Absent flag in legacy input defaults to False without error
# ---------------------------------------------------------------------------


class TestMissingFlagDefaultsFalse:
    def test_schema_defaults_false(self):
        from app.schemas.rules import CustomField

        legacy = CustomField(name="some_field", availability="full")
        assert legacy.requires_gpo is False

    def test_schema_accepts_explicit_true(self):
        from app.schemas.rules import CustomField

        assert CustomField(name="cmdline", requires_gpo=True).requires_gpo is True

    def test_harvest_defaults_false_for_legacy_input(self):
        from app.schemas.rules import CustomField, FieldsFile
        from app.services.fields_harvest import harvest_fields_from_fields_file

        ff = FieldsFile(custom_fields=[CustomField(name="legacy_field")])
        harvest = harvest_fields_from_fields_file(ff)
        assert harvest["legacy_field"].requires_gpo is False