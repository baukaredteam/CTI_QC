"""CSV rulebook importer — MAR-15 / S1.

Seams:
- parse_rules_csv → RulesFile (same schema as parse_rules_file)
- load_shared_bbs + resolve_all_rules on CSV-loaded rules
- summarize_resolution counts (bb_chain / effective_fallback / missing BB)

The 14-rule YAML remains the schema gold standard (regression).
The SOC export CSV is the completeness source (346 unique rules).
"""

from __future__ import annotations

from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = TESTS_DIR.parent
FIXTURES = BACKEND_DIR / "fixtures"

REAL_RULES = FIXTURES / "full_rules85.yaml"
REAL_SHARED = FIXTURES / "shared_bbs.yaml"
SOC_CSV = FIXTURES / "qradar_soc_export.csv"
SOC_SAMPLE = FIXTURES / "qradar_soc_export.sample.csv"

EXPECTED_UNIQUE_RULES = 346
EXPECTED_SHARED_BBS = 67
GOLD_YAML_RULES = 14


# ---------------------------------------------------------------------------
# 1. Regression: 14-rule YAML still parses and resolves
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not REAL_RULES.exists(), reason="full_rules85.yaml not present")
class TestYamlGoldStillGreen:
    def test_yaml_still_parses_exactly_14_rules(self):
        from app.services.rules_parser import parse_rules_file

        rf = parse_rules_file(REAL_RULES)
        assert len(rf.rules) == GOLD_YAML_RULES

    def test_yaml_gold_rule_ids_unchanged(self):
        from app.services.rules_parser import parse_rules_file

        rf = parse_rules_file(REAL_RULES)
        assert [r.rule_id for r in rf.rules] == [
            "INC_0000100",
            "INC_0000200",
            "INC_0001000",
            "INC_0001100",
            "INC_0002100",
            "INC_0002400",
            "INC_0018700",
            "INC_0018900",
            "INC_0019000",
            "INC_0019100",
            "INC_0021100",
            "INC_0021900",
            "INC_0022500",
            "INC_0022700",
        ]

    @pytest.mark.skipif(not REAL_SHARED.exists(), reason="shared_bbs.yaml not present")
    def test_yaml_all_14_still_resolve_without_errors(self):
        from app.services.bb_resolver import load_shared_bbs, resolve_all_rules
        from app.services.rules_parser import parse_rules_file

        rf = parse_rules_file(REAL_RULES)
        shared = load_shared_bbs(REAL_SHARED)
        results = resolve_all_rules(rf, shared)
        assert len(results) == GOLD_YAML_RULES
        assert not any(r.logic_source == "error" for r in results)


# ---------------------------------------------------------------------------
# 2. Shared BB catalog (header may say 85; count the entries)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not REAL_SHARED.exists(), reason="shared_bbs.yaml not present")
class TestSharedBbCatalog:
    def test_shared_bbs_catalog_has_67_entries(self):
        from app.services.bb_resolver import load_shared_bbs

        shared = load_shared_bbs(REAL_SHARED)
        assert len(shared) == EXPECTED_SHARED_BBS


# ---------------------------------------------------------------------------
# 3. Sample CSV (14 gold rows) → same schema as YAML parser
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SOC_SAMPLE.exists(), reason="sample CSV not present")
class TestSampleCsvSchema:
    @pytest.fixture(scope="class")
    @classmethod
    def rules_file(cls):
        from app.services.csv_rules_importer import parse_rules_csv

        return parse_rules_csv(SOC_SAMPLE)

    def test_sample_loads_14_gold_rules(self, rules_file):
        assert len(rules_file.rules) == GOLD_YAML_RULES

    def test_sample_rule_ids_match_yaml_gold(self, rules_file):
        assert [r.rule_id for r in rules_file.rules][0] == "INC_0000100"
        assert "INC_0001000" in [r.rule_id for r in rules_file.rules]

    def test_bb_chain_from_rule_and_bb_columns(self, rules_file):
        rule = next(r for r in rules_file.rules if r.rule_id == "INC_0000100")
        assert rule.building_blocks
        ids = [bb.bb_id for bb in rule.building_blocks]
        assert any("0000100" in bb_id for bb_id in ids)
        assert any("UserUnlock" in bb_id for bb_id in ids)

    def test_sysmon_column_maps_to_flag(self, rules_file):
        whoami = next(r for r in rules_file.rules if r.rule_id == "INC_0002100")
        unlock = next(r for r in rules_file.rules if r.rule_id == "INC_0000100")
        assert whoami.sysmon_required is True
        assert unlock.sysmon_required is False

    def test_mitre_extracted_from_category(self, rules_file):
        rule = next(r for r in rules_file.rules if r.rule_id == "INC_0001000")
        assert "T1204.002" in rule.mitre_techniques
        assert "T1059.003" in rule.mitre_techniques


# ---------------------------------------------------------------------------
# 4. Full CSV: 346 unique rules, no silent drop
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SOC_CSV.exists(), reason="SOC export CSV not present")
class TestFullCsvLoad:
    @pytest.fixture(scope="class")
    @classmethod
    def rules_file(cls):
        from app.services.csv_rules_importer import parse_rules_csv

        return parse_rules_csv(SOC_CSV)

    def test_csv_load_count_is_346(self, rules_file):
        assert len(rules_file.rules) == EXPECTED_UNIQUE_RULES

    def test_rule_ids_are_unique(self, rules_file):
        ids = [r.rule_id for r in rules_file.rules]
        assert len(ids) == len(set(ids)) == EXPECTED_UNIQUE_RULES

    def test_no_silent_skip_of_named_rows(self, rules_file):
        assert rules_file.metadata.get("unique_rules") == EXPECTED_UNIQUE_RULES
        assert rules_file.metadata.get("skipped_named") == 0


# ---------------------------------------------------------------------------
# 5. Parser + resolver report: bb_chain / fallback / missing BB
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not SOC_CSV.exists() or not REAL_SHARED.exists(),
    reason="CSV or shared_bbs.yaml not present",
)
class TestCsvResolutionReport:
    @pytest.fixture(scope="class")
    @classmethod
    def summary(cls):
        from app.services.bb_resolver import (
            load_shared_bbs,
            resolve_all_rules,
            summarize_resolution,
        )
        from app.services.csv_rules_importer import parse_rules_csv

        rf = parse_rules_csv(SOC_CSV)
        shared = load_shared_bbs(REAL_SHARED)
        results = resolve_all_rules(rf, shared)
        return summarize_resolution(results), results

    def test_every_csv_rule_is_in_the_report(self, summary):
        report, results = summary
        assert report.total_rules == EXPECTED_UNIQUE_RULES
        assert len(results) == EXPECTED_UNIQUE_RULES

    def test_report_has_bb_chain_fallback_and_missing_counts(self, summary):
        report, _results = summary
        assert report.bb_chain >= 1
        assert report.effective_fallback >= 0
        assert report.bb_chain + report.effective_fallback + report.errors == EXPECTED_UNIQUE_RULES
        # Missing BB is a counted field, never a silent skip
        assert report.rules_with_missing_bb >= 0
        assert report.missing_bb_count == len(report.missing_bb_ids)

    def test_missing_bb_ids_are_listed_when_present(self, summary):
        report, results = summary
        if report.rules_with_missing_bb:
            assert report.missing_bb_ids
            warned = [
                r.rule_id
                for r in results
                if any(w.warning_type == "missing_building_block" for w in r.warnings)
            ]
            assert len(warned) == report.rules_with_missing_bb

    def test_print_report_includes_counts(self, summary, capsys):
        from app.services.bb_resolver import print_resolution_report

        _report, results = summary
        print_resolution_report(results)
        out = capsys.readouterr().out
        assert "BB Resolution Report" in out
        assert "Fully resolved (bb_chain)" in out
        assert "Effective fallback" in out
        assert "Rules with missing BBs" in out


# ---------------------------------------------------------------------------
# 6. Format facts: ';' delimiter, English columns, garbled header still works
# ---------------------------------------------------------------------------

class TestCsvFormatFacts:
    def test_semicolon_delimiter_and_garbled_header(self, tmp_path):
        from app.services.csv_rules_importer import parse_rules_csv

        # Cyrillic header bytes decoded as the wrong codec → mojibake,
        # but English Rule/BB/SYSMON names stay usable.
        path = tmp_path / "garbled.csv"
        path.write_text(
            "ID;\ufffd\ufffd\ufffd;log source;enabled;created;modified;category;criticality;Rule;BB;BB2;BB3;BB4;BB5;SYSMON\n"
            "1;Unlock;Microsoft Windows Security Event Log;true;2020-09-24;2023-03-30;T1078;Medium;"
            "INC_0000100_common:Multiple_Account_Unlock_by_One_User_Windows;"
            "BB_eventype:UserUnlock_Windows;;;;;no\n",
            encoding="utf-8",
        )
        rf = parse_rules_csv(path)
        assert len(rf.rules) == 1
        assert rf.rules[0].rule_id == "INC_0000100"
        assert rf.rules[0].rule_name == "Multiple_Account_Unlock_by_One_User_Windows"
        assert any("UserUnlock" in bb.bb_id for bb in rf.rules[0].building_blocks)

    def test_duplicate_rule_does_not_inflate_unique_count(self, tmp_path):
        from app.services.csv_rules_importer import parse_rules_csv

        path = tmp_path / "dups.csv"
        header = "ID;Rules in Qradar;log source;enabled;created;modified;category;criticality;Rule;BB;BB2;BB3;BB4;BB5;SYSMON"
        row = (
            "1;Unlock;Microsoft Windows Security Event Log;true;2020-09-24;2023-03-30;T1078;Medium;"
            "INC_0000100_common:Multiple_Account_Unlock_by_One_User_Windows;"
            "BB_eventype:UserUnlock_Windows;;;;;no"
        )
        path.write_text(header + "\n" + row + "\n" + row + "\n", encoding="utf-8")
        rf = parse_rules_csv(path)
        assert len(rf.rules) == 1
        assert rf.metadata.get("duplicates") == 1
