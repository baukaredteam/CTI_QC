"""M2 test suite — Rules parser, fields harvest, and constants.

Unit tests use the synthetic sample_rules.yaml fixture.
Acceptance tests use the real full_rules85.yaml and fields.yaml fixtures
(skip-if-missing so CI doesn't break without client data).

Covers:
1. strip_yaml_values helper — strings, dicts, lists, nested
2. parse_rules_file — synthetic fixture: rule count, strip, metadata ignored
3. Sysmon split — synthetic fixture
4. Custom fields harvest — partial availability, HIGH adversary
5. INDEXED_FIELDS constants
6. Acceptance: real full_rules85.yaml → 14 rules, 7/7 sysmon, 8 cmdline partial
7. Acceptance: real fields.yaml → fields parsed with strip
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TESTS_DIR = Path(__file__).resolve().parent.parent          # backend/tests
FIXTURES_DIR = TESTS_DIR / "fixtures"                       # backend/tests/fixtures
SAMPLE_RULES = FIXTURES_DIR / "sample_rules.yaml"

# Real client fixtures live outside tests/
BACKEND_DIR = TESTS_DIR.parent                              # backend/
REAL_RULES = BACKEND_DIR / "fixtures" / "full_rules85.yaml"
REAL_FIELDS = BACKEND_DIR / "fixtures" / "fields.yaml"


# ---------------------------------------------------------------------------
# 1. strip_yaml_values
# ---------------------------------------------------------------------------

class TestStripYamlValues:
    def test_strips_string(self):
        from app.services.constants import strip_yaml_values
        assert strip_yaml_values("  hello  ") == "hello"

    def test_strips_dict_keys_and_values(self):
        from app.services.constants import strip_yaml_values
        result = strip_yaml_values({" key ": " value "})
        assert result == {"key": "value"}

    def test_strips_list_elements(self):
        from app.services.constants import strip_yaml_values
        result = strip_yaml_values(["  a ", " b  "])
        assert result == ["a", "b"]

    def test_nested_structure(self):
        from app.services.constants import strip_yaml_values
        data = {
            " name ": " INC_001 ",
            "items": [" T1059 ", {"nested ": " val "}],
        }
        result = strip_yaml_values(data)
        assert result["name"] == "INC_001"
        assert result["items"][0] == "T1059"
        assert result["items"][1]["nested"] == "val"

    def test_preserves_non_strings(self):
        from app.services.constants import strip_yaml_values
        data = {"count": 42, "enabled": True, "nothing": None}
        result = strip_yaml_values(data)
        assert result == data


# ---------------------------------------------------------------------------
# 2. parse_rules_file — synthetic fixture
# ---------------------------------------------------------------------------

class TestParseRulesFileSynthetic:
    @pytest.fixture(scope="class")
    @classmethod
    def rules_file(cls):
        from app.services.rules_parser import parse_rules_file
        return parse_rules_file(SAMPLE_RULES)

    def test_parses_three_rules(self, rules_file):
        assert len(rules_file.rules) == 3

    def test_metadata_not_turned_into_rule(self, rules_file):
        """metadata block must NOT become a rule."""
        rule_ids = [r.rule_id for r in rules_file.rules]
        assert "metadata" not in rule_ids
        # metadata is stored separately
        assert rules_file.metadata.get("total_rules") == 100

    def test_fixes_applied_stored(self, rules_file):
        assert "Test fix applied" in rules_file.fixes_applied

    def test_trailing_spaces_stripped_from_rule_id(self, rules_file):
        """rule_id "TEST_001 " must become "TEST_001" after strip."""
        r0 = rules_file.rules[0]
        assert r0.rule_id == "TEST_001"
        assert r0.rule_name == "Dirty_Trailing_Space_Rule"

    def test_trailing_spaces_stripped_from_criticality(self, rules_file):
        r0 = rules_file.rules[0]
        assert r0.criticality == "High"

    def test_trailing_spaces_stripped_from_mitre(self, rules_file):
        r0 = rules_file.rules[0]
        assert "T1059.001" in r0.mitre_techniques  # was "T1059.001 "
        for t in r0.mitre_techniques:
            assert t == t.strip()

    def test_trailing_spaces_stripped_from_bb_name(self, rules_file):
        r0 = rules_file.rules[0]
        bb0 = r0.building_blocks[0]
        assert bb0.bb_name == "Dirty_BB"

    def test_trailing_spaces_stripped_from_depends_on(self, rules_file):
        r0 = rules_file.rules[0]
        bb0 = r0.building_blocks[0]
        for dep in bb0.depends_on_bb:
            assert dep == dep.strip()

    def test_trailing_spaces_stripped_from_custom_field_name(self, rules_file):
        r0 = rules_file.rules[0]
        names = [cf.name for cf in r0.custom_fields]
        assert "proc_file_path" in names  # was "proc_file_path "
        assert "cmdline" in names         # was "cmdline "
        for cf in r0.custom_fields:
            assert cf.name == cf.name.strip()
            assert cf.availability == cf.availability.strip()

    def test_degraded_regex_preserved_not_validated(self, rules_file):
        r"""Degraded regex like '.\cmd.exe' is kept as-is (NOT validated)."""
        r0 = rules_file.rules[0]
        bb0 = r0.building_blocks[0]
        # The single-dot regex is preserved verbatim
        assert ".\\cmd.exe" in bb0.own_conditions or ".cmd.exe" in bb0.own_conditions

    def test_reference_sets_parsed(self, rules_file):
        r1 = rules_file.rules[1]
        assert "RMS_test_ref_set" in r1.reference_sets_used


# ---------------------------------------------------------------------------
# 3. Sysmon split — synthetic
# ---------------------------------------------------------------------------

class TestSysmonSplitSynthetic:
    @pytest.fixture(scope="class")
    @classmethod
    def rules_file(cls):
        from app.services.rules_parser import parse_rules_file
        return parse_rules_file(SAMPLE_RULES)

    def test_sysmon_split(self, rules_file):
        sysmon_true = sum(1 for r in rules_file.rules if r.sysmon_required)
        sysmon_false = len(rules_file.rules) - sysmon_true
        assert sysmon_true == 1   # TEST_002
        assert sysmon_false == 2  # TEST_001, TEST_003


# ---------------------------------------------------------------------------
# 4. Fields harvest — synthetic
# ---------------------------------------------------------------------------

class TestFieldsHarvestSynthetic:
    @pytest.fixture(scope="class")
    @classmethod
    def harvest(cls):
        from app.services.rules_parser import parse_rules_file
        from app.services.fields_harvest import harvest_fields_from_rules
        rf = parse_rules_file(SAMPLE_RULES)
        return harvest_fields_from_rules(rf)

    def test_harvests_unique_fields(self, harvest):
        # proc_file_path and cmdline from all rules
        assert "proc_file_path" in harvest
        assert "cmdline" in harvest

    def test_partial_availability_tracked(self, harvest):
        from app.services.fields_harvest import get_partial_fields
        partial = get_partial_fields(harvest)
        assert "cmdline" in partial

    def test_high_adversary_tracked(self, harvest):
        from app.services.fields_harvest import get_high_adversary_fields
        high = get_high_adversary_fields(harvest)
        assert "cmdline" in high
        assert "proc_file_path" in high

    def test_used_in_rules_tracked(self, harvest):
        hf = harvest["cmdline"]
        assert "TEST_001" in hf.used_in_rules
        assert "TEST_003" in hf.used_in_rules


# ---------------------------------------------------------------------------
# 5. INDEXED_FIELDS constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_indexed_fields_are_frozenset(self):
        from app.services.constants import INDEXED_FIELDS
        assert isinstance(INDEXED_FIELDS, frozenset)

    def test_qid_in_indexed(self):
        from app.services.constants import INDEXED_FIELDS
        assert "qid" in INDEXED_FIELDS

    def test_eventid_not_in_indexed(self):
        from app.services.constants import INDEXED_FIELDS, SEMANTIC_FILTER_FIELDS
        assert "eventid" not in INDEXED_FIELDS
        assert "eventid" in SEMANTIC_FILTER_FIELDS


# ---------------------------------------------------------------------------
# 6. Acceptance: real full_rules85.yaml
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not REAL_RULES.exists(),
    reason="Real fixture full_rules85.yaml not present",
)
class TestRealRulesAcceptance:
    @pytest.fixture(scope="class")
    @classmethod
    def rules_file(cls):
        from app.services.rules_parser import parse_rules_file
        return parse_rules_file(REAL_RULES)

    def test_parses_exactly_14_rules(self, rules_file):
        assert len(rules_file.rules) == 14

    def test_metadata_not_turned_into_rule(self, rules_file):
        rule_ids = [r.rule_id for r in rules_file.rules]
        # metadata key exists but is NOT a rule
        assert rules_file.metadata.get("total_rules") == 346
        assert "metadata" not in rule_ids

    def test_sysmon_split_7_7(self, rules_file):
        sysmon_true = sum(1 for r in rules_file.rules if r.sysmon_required)
        sysmon_false = len(rules_file.rules) - sysmon_true
        assert sysmon_true == 7, "Expected 7 sysmon_required=true, got %d" % sysmon_true
        assert sysmon_false == 7, "Expected 7 sysmon_required=false, got %d" % sysmon_false

    def test_cmdline_partial_in_8_rules(self, rules_file):
        count = 0
        for r in rules_file.rules:
            for cf in r.custom_fields:
                if cf.name == "cmdline" and cf.availability == "partial":
                    count += 1
                    break
        assert count == 8, "Expected 8 rules with cmdline partial, got %d" % count

    def test_all_rule_ids_stripped(self, rules_file):
        for r in rules_file.rules:
            assert r.rule_id == r.rule_id.strip()
            assert r.criticality == r.criticality.strip()

    def test_no_trailing_spaces_in_mitre(self, rules_file):
        for r in rules_file.rules:
            for t in r.mitre_techniques:
                assert t == t.strip(), "MITRE technique '%s' has trailing space" % t

    def test_print_summary(self, rules_file, capsys):
        from app.services.rules_parser import print_rules_summary
        print_rules_summary(rules_file)
        captured = capsys.readouterr()
        assert "Total rules parsed" in captured.out
        assert "14" in captured.out


# ---------------------------------------------------------------------------
# 7. Acceptance: real fields.yaml
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not REAL_FIELDS.exists(),
    reason="Real fixture fields.yaml not present",
)
class TestRealFieldsAcceptance:
    @pytest.fixture(scope="class")
    @classmethod
    def fields_file(cls):
        from app.services.rules_parser import parse_fields_file
        return parse_fields_file(REAL_FIELDS)

    def test_parses_fields(self, fields_file):
        assert len(fields_file.custom_fields) > 0

    def test_all_field_names_stripped(self, fields_file):
        for cf in fields_file.custom_fields:
            assert cf.name == cf.name.strip()
            assert cf.availability == cf.availability.strip()

    def test_metadata_present(self, fields_file):
        assert fields_file.metadata.get("siem") is not None

    def test_proc_cmdline_present(self, fields_file):
        names = [cf.name for cf in fields_file.custom_fields]
        assert "proc_cmdline" in names
