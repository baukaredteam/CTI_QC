"""M3 test suite — Building-block resolver.

Covers:
1. Resolve INC_0001000 end-to-end (real fixtures, skip-if-missing)
2. Circular dependency → ResolutionError with cycle path
3. Dangling reference → MissingBuildingBlock warning, no crash
4. BB_0001100 comment-only own_conditions treated as empty
5. All 14 rules resolution report (real fixtures, skip-if-missing)
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

TESTS_DIR = Path(__file__).resolve().parent.parent          # backend/tests
BACKEND_DIR = TESTS_DIR.parent                              # backend/
REAL_RULES = BACKEND_DIR / "fixtures" / "full_rules85.yaml"
REAL_SHARED = BACKEND_DIR / "fixtures" / "shared_bbs.yaml"


# ---------------------------------------------------------------------------
# Helpers: synthetic BB data for unit tests
# ---------------------------------------------------------------------------

def _make_synthetic_rule(**overrides):
    """Create a minimal Rule object for testing."""
    from app.schemas.rules import Rule, BuildingBlock

    defaults = dict(
        rule_id="SYNTH_001",
        rule_name="Synthetic_Test_Rule",
        enabled=True,
        log_source="Microsoft Windows Security Event Log",
        criticality="Medium",
        mitre_techniques=["T1059"],
        sysmon_required=False,
        building_blocks=[
            BuildingBlock(
                bb_id="BB_SYNTH_001",
                bb_name="Synth_BB",
                level=1,
                depends_on_bb=["BB_eventtype:ProcessCreate"],
                own_conditions="proc_file_path IMATCHES '.*\\\\cmd\\.exe'",
            ),
            BuildingBlock(
                bb_id="BB_eventtype:ProcessCreate",
                bb_name="ProcessCreate",
                level=2,
                depends_on_bb=["BB_logsource:Windows_to_refactor"],
                own_conditions="event_id = 4688",
            ),
        ],
        effective_detection_logic="event_id = 4688 AND proc_file_path = cmd.exe",
    )
    defaults.update(overrides)
    return Rule(**defaults)


def _make_shared_lookup():
    """Create a minimal shared BB lookup for synthetic tests."""
    return {
        "BB_logsource:Windows_to_refactor": {
            "bb_id": "BB_logsource:Windows_to_refactor",
            "bb_name": "Log source type - Windows_to_refactor",
            "level": 3,
            "depends_on_bb": [],
            "own_conditions": "Log Source Type = Microsoft Windows Security Event Log",
        },
        "BB_logsource:Sysmon": {
            "bb_id": "BB_logsource:Sysmon",
            "bb_name": "Log source type - Sysmon",
            "level": 3,
            "depends_on_bb": [],
            "own_conditions": "Log Source Type = Sysmon",
        },
    }


# ---------------------------------------------------------------------------
# 1. Synthetic: basic BB chain resolution
# ---------------------------------------------------------------------------

class TestBBResolverSynthetic:
    def test_resolves_chain_depth_first(self):
        """Conditions appear leaf-first: log source → event type → rule BB."""
        from app.services.bb_resolver import resolve_rule

        rule = _make_synthetic_rule()
        shared = _make_shared_lookup()
        result = resolve_rule(rule, shared)

        assert result.logic_source == "bb_chain"
        assert len(result.merged_conditions) == 3
        # Leaf (log source) comes first
        assert "Log Source Type" in result.merged_conditions[0]
        # Then event type filter
        assert "4688" in result.merged_conditions[1]
        # Then rule-level condition
        assert "cmd" in result.merged_conditions[2]

    def test_bb_chain_recorded(self):
        from app.services.bb_resolver import resolve_rule

        rule = _make_synthetic_rule()
        shared = _make_shared_lookup()
        result = resolve_rule(rule, shared)

        assert "BB_SYNTH_001" in result.bb_chain
        assert "BB_eventtype:ProcessCreate" in result.bb_chain
        assert "BB_logsource:Windows_to_refactor" in result.bb_chain

    def test_field_names_extracted(self):
        from app.services.bb_resolver import resolve_rule

        rule = _make_synthetic_rule()
        shared = _make_shared_lookup()
        result = resolve_rule(rule, shared)

        assert "proc_file_path" in result.referenced_fields
        assert "event_id" in result.referenced_fields


# ---------------------------------------------------------------------------
# 2. Circular dependency → ResolutionError
# ---------------------------------------------------------------------------

class TestCircularDependency:
    def test_raises_resolution_error(self):
        from app.schemas.rules import Rule, BuildingBlock
        from app.services.bb_resolver import resolve_rule
        from app.schemas.resolved_detection import ResolutionError

        rule = Rule(
            rule_id="CIRC_001",
            rule_name="Circular_Test",
            building_blocks=[
                BuildingBlock(
                    bb_id="BB_A",
                    level=1,
                    depends_on_bb=["BB_B"],
                    own_conditions="field_a = 1",
                ),
                BuildingBlock(
                    bb_id="BB_B",
                    level=2,
                    depends_on_bb=["BB_A"],
                    own_conditions="field_b = 2",
                ),
            ],
        )

        with pytest.raises(ResolutionError) as exc_info:
            resolve_rule(rule, {})

        assert exc_info.value.cycle_path
        assert "BB_A" in exc_info.value.cycle_path

    def test_cycle_path_has_both_nodes(self):
        from app.schemas.rules import Rule, BuildingBlock
        from app.services.bb_resolver import resolve_rule
        from app.schemas.resolved_detection import ResolutionError

        rule = Rule(
            rule_id="CIRC_002",
            building_blocks=[
                BuildingBlock(bb_id="BB_X", level=1, depends_on_bb=["BB_Y"]),
                BuildingBlock(bb_id="BB_Y", level=2, depends_on_bb=["BB_Z"]),
                BuildingBlock(bb_id="BB_Z", level=3, depends_on_bb=["BB_X"]),
            ],
        )

        with pytest.raises(ResolutionError) as exc_info:
            resolve_rule(rule, {})

        path = exc_info.value.cycle_path
        assert "BB_X" in path


# ---------------------------------------------------------------------------
# 3. Dangling reference → MissingBuildingBlock warning, no crash
# ---------------------------------------------------------------------------

class TestDanglingReference:
    def test_missing_bb_emits_warning(self):
        from app.schemas.rules import Rule, BuildingBlock
        from app.services.bb_resolver import resolve_rule

        rule = Rule(
            rule_id="DANG_001",
            rule_name="Dangling_Test",
            building_blocks=[
                BuildingBlock(
                    bb_id="BB_DANG",
                    level=1,
                    depends_on_bb=["BB_DOES_NOT_EXIST"],
                    own_conditions="field_x = 42",
                ),
            ],
            effective_detection_logic="field_x = 42 fallback",
        )

        result = resolve_rule(rule, {})

        # Should NOT crash
        assert result.rule_id == "DANG_001"
        # Should have a warning
        missing_warnings = [w for w in result.warnings if w.warning_type == "missing_building_block"]
        assert len(missing_warnings) == 1
        assert "BB_DOES_NOT_EXIST" in missing_warnings[0].bb_id

    def test_rest_of_rule_still_resolves(self):
        from app.schemas.rules import Rule, BuildingBlock
        from app.services.bb_resolver import resolve_rule

        rule = Rule(
            rule_id="DANG_002",
            building_blocks=[
                BuildingBlock(
                    bb_id="BB_GOOD",
                    level=1,
                    depends_on_bb=["BB_MISSING"],
                    own_conditions="good_field = 1",
                ),
            ],
        )

        result = resolve_rule(rule, {})

        # The good BB's conditions should still be collected
        assert result.logic_source == "bb_chain"
        assert any("good_field" in c for c in result.merged_conditions)


# ---------------------------------------------------------------------------
# 4. Comment-only own_conditions treated as empty
# ---------------------------------------------------------------------------

class TestCommentOnlyConditions:
    def test_comment_only_skipped(self):
        from app.services.bb_resolver import _is_empty_conditions
        assert _is_empty_conditions("# All conditions in depends_on_bb")
        assert _is_empty_conditions("  # Comment\n  \n")
        assert _is_empty_conditions("")
        assert _is_empty_conditions("   ")

    def test_real_conditions_not_skipped(self):
        from app.services.bb_resolver import _is_empty_conditions
        assert not _is_empty_conditions("event_id = 4688")
        assert not _is_empty_conditions("# comment\nevent_id = 4688")

    def test_composite_bb_contributes_no_own_conditions(self):
        """BB_0001100 has comment-only own_conditions; merged conditions
        should come purely from its depends_on_bb."""
        from app.schemas.rules import Rule, BuildingBlock
        from app.services.bb_resolver import resolve_rule

        rule = Rule(
            rule_id="COMP_001",
            building_blocks=[
                BuildingBlock(
                    bb_id="BB_COMPOSITE",
                    level=1,
                    depends_on_bb=["BB_DEP"],
                    own_conditions="# All conditions in depends_on_bb\n",
                ),
                BuildingBlock(
                    bb_id="BB_DEP",
                    level=2,
                    depends_on_bb=[],
                    own_conditions="event_id = 4688",
                ),
            ],
        )

        result = resolve_rule(rule, {})

        # Only the dependency's conditions should appear
        assert len(result.merged_conditions) == 1
        assert "4688" in result.merged_conditions[0]


# ---------------------------------------------------------------------------
# 5. Normalize corrupted BB IDs
# ---------------------------------------------------------------------------

class TestCorruptedIdNormalization:
    def test_normalize_strips_internal_whitespace(self):
        from app.services.bb_resolver import _normalize_bb_id
        assert _normalize_bb_id("BB_logsource:Windo ws_to_refactor") == "BB_logsource:Windows_to_refactor"
        assert _normalize_bb_id("BB_common:Rundll32_T ool_Windows") == "BB_common:Rundll32_Tool_Windows"
        assert _normalize_bb_id("BB_common:Reg _Tool_Windows") == "BB_common:Reg_Tool_Windows"
        assert _normalize_bb_id("BB_common:Mshta_Tool_Wind ows") == "BB_common:Mshta_Tool_Windows"

    def test_corrupted_ref_resolves_via_normalization(self):
        from app.schemas.rules import Rule, BuildingBlock
        from app.services.bb_resolver import resolve_rule

        shared = {
            "BB_logsource:Windows_to_refactor": {
                "bb_id": "BB_logsource:Windows_to_refactor",
                "depends_on_bb": [],
                "own_conditions": "Log Source Type = Windows",
            },
        }

        rule = Rule(
            rule_id="NORM_001",
            building_blocks=[
                BuildingBlock(
                    bb_id="BB_TEST",
                    level=1,
                    depends_on_bb=["BB_logsource:Windo ws_to_refactor"],
                    own_conditions="test = 1",
                ),
            ],
        )

        result = resolve_rule(rule, shared)
        # Should resolve via normalization
        assert result.logic_source == "bb_chain"
        assert any("Log Source Type" in c for c in result.merged_conditions)


# ---------------------------------------------------------------------------
# 6. Effective fallback when no BBs
# ---------------------------------------------------------------------------

class TestEffectiveFallback:
    def test_falls_back_when_no_building_blocks(self):
        from app.schemas.rules import Rule
        from app.services.bb_resolver import resolve_rule

        rule = Rule(
            rule_id="FB_001",
            building_blocks=[],
            effective_detection_logic="event_id = 4688 AND cmdline = whoami",
        )

        result = resolve_rule(rule, {})
        assert result.logic_source == "effective_fallback"
        assert any("whoami" in c for c in result.merged_conditions)


# ---------------------------------------------------------------------------
# 7. Real fixtures: resolve INC_0001000 end-to-end
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not REAL_RULES.exists() or not REAL_SHARED.exists(),
    reason="Real fixtures not present",
)
class TestRealINC0001000:
    @pytest.fixture(scope="class")
    @classmethod
    def resolved(cls):
        from app.services.rules_parser import parse_rules_file
        from app.services.bb_resolver import resolve_rule, load_shared_bbs

        rf = parse_rules_file(REAL_RULES)
        shared = load_shared_bbs(REAL_SHARED)

        rule = next(r for r in rf.rules if r.rule_id == "INC_0001000")
        return resolve_rule(rule, shared)

    def test_logic_source_is_bb_chain(self, resolved):
        assert resolved.logic_source == "bb_chain"

    def test_chain_reaches_terminal_log_source(self, resolved):
        assert "BB_logsource:Windows_to_refactor" in resolved.bb_chain

    def test_event_id_4688_in_conditions(self, resolved):
        all_text = " ".join(resolved.merged_conditions)
        assert "4688" in all_text

    def test_office_parent_condition_present(self, resolved):
        all_text = " ".join(resolved.merged_conditions)
        # Should have the MS Office parent process condition
        assert "excel" in all_text.lower() or "winword" in all_text.lower()

    def test_cmd_condition_present(self, resolved):
        all_text = " ".join(resolved.merged_conditions)
        assert "cmd" in all_text.lower()


# ---------------------------------------------------------------------------
# 8. Real fixtures: resolve INC_0001100 (composite BB, comment-only)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not REAL_RULES.exists() or not REAL_SHARED.exists(),
    reason="Real fixtures not present",
)
class TestRealINC0001100:
    @pytest.fixture(scope="class")
    @classmethod
    def resolved(cls):
        from app.services.rules_parser import parse_rules_file
        from app.services.bb_resolver import resolve_rule, load_shared_bbs

        rf = parse_rules_file(REAL_RULES)
        shared = load_shared_bbs(REAL_SHARED)

        rule = next(r for r in rf.rules if r.rule_id == "INC_0001100")
        return resolve_rule(rule, shared)

    def test_logic_source_is_bb_chain(self, resolved):
        assert resolved.logic_source == "bb_chain"

    def test_composite_bb_has_no_own_conditions(self, resolved):
        """BB_0001100 has comment-only own_conditions; its conditions
        should come from depends_on_bb (ProcessCreate, Office parent, Powershell)."""
        all_text = " ".join(resolved.merged_conditions)
        # Should have powershell condition from BB_common:Powershell_by_Process (inline)
        assert "powershell" in all_text.lower()


# ---------------------------------------------------------------------------
# 9. Real fixtures: resolve all 14 rules + print report
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not REAL_RULES.exists() or not REAL_SHARED.exists(),
    reason="Real fixtures not present",
)
class TestRealAllRulesResolution:
    @pytest.fixture(scope="class")
    @classmethod
    def results(cls):
        from app.services.rules_parser import parse_rules_file
        from app.services.bb_resolver import resolve_all_rules, load_shared_bbs

        rf = parse_rules_file(REAL_RULES)
        shared = load_shared_bbs(REAL_SHARED)
        return resolve_all_rules(rf, shared)

    def test_all_14_rules_resolved(self, results):
        assert len(results) == 14

    def test_no_errors(self, results):
        errors = [r for r in results if r.logic_source == "error"]
        assert len(errors) == 0

    def test_most_rules_are_bb_chain(self, results):
        bb_chain = [r for r in results if r.logic_source == "bb_chain"]
        assert len(bb_chain) >= 12  # at least 12 of 14 should resolve from BB chain

    def test_print_report(self, results, capsys):
        from app.services.bb_resolver import print_resolution_report
        print_resolution_report(results)
        captured = capsys.readouterr()
        assert "BB Resolution Report" in captured.out
        assert "14" in captured.out
