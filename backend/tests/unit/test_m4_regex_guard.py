"""Unit tests for the regex guard (M4.1).

Tests cover:
  - pure-path detection (synthetic degraded patterns)
  - real-string examples (leading star loss, invalid regex)
  - guard_conditions: net operation, multiple patterns, no mutation
  - real fixture data (shared_bbs.yaml): asserts no false positives on real data
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.regex_guard import (
    extract_imatches_patterns,
    guard_conditions,
    is_degraded_pattern,
)

# ---------------------------------------------------------------------------
# is_degraded_pattern — degraded (True)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        r".\cmd.exe",  # leading dot, no star — degraded
        r".\powershell.exe",
        r".\regsvr32.exe",
        r".\mshta.exe",
        r"(unbalanced",  # invalid regex — re.error
        r"[invalid",  # invalid regex — re.error
    ],
)
def test_is_degraded_pattern_true(pattern: str) -> None:
    assert is_degraded_pattern(pattern) is True


# ---------------------------------------------------------------------------
# is_degraded_pattern — non-degraded (False)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        r".*\\cmd\.exe",  # leading .* — NOT degraded
        r".*\\powershell\.exe",
        r".*FromBase64String.*",
        r".*",
        r"^foo$",
        r"bar",
        r"",  # empty — compiles, no leading dot
        r".*",  # bare .* — NOT degraded
        r".foo",  # bare leading dot with no backslash — NOT the lost-star mangle
    ],
)
def test_is_degraded_pattern_false(pattern: str) -> None:
    assert is_degraded_pattern(pattern) is False


def test_is_degraded_pattern_none_returns_false() -> None:
    assert is_degraded_pattern(None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# extract_imatches_patterns
# ---------------------------------------------------------------------------


def test_extract_imatches_single() -> None:
    text = "proc_file_path IMATCHES '.*\\\\cmd\\.exe'"
    assert extract_imatches_patterns(text) == [r".*\\cmd\.exe"]


def test_extract_imatches_multiple_in_one_string() -> None:
    text = (
        "cmdline IMATCHES '.*-decode.*' "
        "OR cmdline IMATCHES '.*-decodehex.*'"
    )
    assert extract_imatches_patterns(text) == [r".*-decode.*", r".*-decodehex.*"]


def test_extract_imatches_none() -> None:
    assert extract_imatches_patterns("no imatches here") == []
    assert extract_imatches_patterns("") == []


def test_extract_imatches_case_insensitive() -> None:
    text = "field imatches 'pattern'"
    assert extract_imatches_patterns(text) == ["pattern"]


# ---------------------------------------------------------------------------
# guard_conditions: net operation, no mutation, multiplicity
# ---------------------------------------------------------------------------


def test_guard_conditions_detects_degraded() -> None:
    conditions = ["proc_file_path IMATCHES '.\\cmd.exe'"]
    warnings = guard_conditions(conditions)
    assert len(warnings) == 1
    assert warnings[0].code == "REGEX_DEGRADED"
    assert warnings[0].severity == "warning"
    assert warnings[0].pattern == r".\cmd.exe"


def test_guard_conditions_no_false_positive_on_star_prefix() -> None:
    conditions = ["proc_file_path IMATCHES '.*\\cmd\\.exe'"]
    assert guard_conditions(conditions) == []


def test_guard_conditions_does_not_mutate_input() -> None:
    conditions = ["proc_file_path IMATCHES '.\\cmd.exe'"]
    original = list(conditions)
    guard_conditions(conditions)
    assert conditions == original


def test_guard_conditions_multiple_patterns_one_condition() -> None:
    conditions = [
        "cmdline IMATCHES '.\\bad\\.exe' OR cmdline IMATCHES '.*good\\.exe'"
    ]
    warnings = guard_conditions(conditions)
    assert len(warnings) == 1
    assert warnings[0].pattern == r".\bad\.exe"


def test_guard_conditions_multiple_conditions() -> None:
    conditions = [
        "proc_file_path IMATCHES '.\\cmd.exe'",
        "proc_file_path IMATCHES '.*\\powershell\\.exe'",
        "cmdline IMATCHES '(unbalanced'",
    ]
    warnings = guard_conditions(conditions)
    assert len(warnings) == 2
    patterns = {w.pattern for w in warnings}
    assert r".\cmd.exe" in patterns
    assert "(unbalanced" in patterns


def test_guard_conditions_empty_input() -> None:
    assert guard_conditions([]) == []
    assert guard_conditions([""]) == []
    assert guard_conditions(None) == []  # type: ignore[arg-type]


def test_guard_conditions_invalid_regex_is_degraded() -> None:
    conditions = ["cmdline IMATCHES '[invalid'"]
    warnings = guard_conditions(conditions)
    assert len(warnings) == 1
    assert warnings[0].pattern == "[invalid"


# ---------------------------------------------------------------------------
# Real fixture data (shared_bbs.yaml) — guard must not flag real patterns
# as degraded unless they really are. Integration-style guard: asserts no
# false positives on the actual fixture.
# ---------------------------------------------------------------------------

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "shared_bbs.yaml"


def _collect_own_conditions_from_fixture() -> list[str]:
    """Parse shared_bbs.yaml and return every own_conditions string."""
    if not _FIXTURE.exists():
        pytest.skip(f"fixture not found: {_FIXTURE}")
    import yaml  # local import; only needed for real-fixture integration

    data = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    conditions: list[str] = []
    buildings = data.get("building_blocks", data) if isinstance(data, dict) else data
    if buildings is None:
        return conditions
    blocks = buildings if isinstance(buildings, list) else buildings.values()
    for block in blocks:
        if not isinstance(block, dict):
            continue
        oc = block.get("own_conditions")
        if isinstance(oc, str) and oc.strip():
            conditions.append(oc)
        elif isinstance(oc, list):
            conditions.extend(c for c in oc if isinstance(c, str) and c.strip())
    return conditions


def test_real_fixture_no_degraded_patterns() -> None:
    conditions = _collect_own_conditions_from_fixture()
    if not conditions:
        pytest.skip("no own_conditions in fixture")
    warnings = guard_conditions(conditions)
    # Real fixture patterns should NOT be flagged as degraded. If the fixture
    # is later updated to include a genuinely degraded pattern, this test will
    # fail and force the author to either fix the fixture or update the guard.
    assert warnings == [], (
        "Regex guard flagged patterns in the real fixture as degraded: "
        f"{[w.pattern for w in warnings]}. "
        "Either fix the fixture or update this test if the patterns are "
        "intentionally degraded."
    )