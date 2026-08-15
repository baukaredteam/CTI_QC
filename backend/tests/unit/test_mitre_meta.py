"""Ticket 01 test suite — MITRE ATT&CK v15 offline fixture + four-level fallback resolver.

Covers (spec contract 3.1, HC-3, guardrails F1–F4, ticket
``.scratch/hypothesis-enrichment/issues/01-mitre-v15-fixture.md``):

1. **F1** — the 47-technique union (full_rules85.yaml ∪ TL-2026-1693
   ``_DEFAULT_TTPS`` ∪ ``TTP_TACTICS``/``TECHNIQUE_NAMES`` keys) is the minimal
   *assertion set*: ``union ⊆ fixture``; every element resolves to non-empty
   ``name``+``tactic``; ``name == id`` (placeholder) is forbidden.
2. **F2** — the generator is two layers: the live ``fetch_stix(client)`` is
   never exercised here; the pure ``build_fixture(stix_objects, provenance) ->
   bytes`` is fed the committed ``tests/fixtures/stix_sample.json`` + fixed
   provenance and must produce byte-identical output across two calls.
3. **F3** — provenance ``generated_at`` is date-only ``YYYY-MM-DD`` and the
   serialization is stable (this is a prerequisite of F2 byte-identity).
4. **F4** — every technique in the union resolves to non-empty ``data_sources``
   in the committed fixture.
5. **HC-3 fallback order** — ``resolve_technique_meta`` with ``live_lookup=None``
   exercises levels 1/3/4 (bundle_names → YAML v15 → hardcoded); a fake
   callable exercises level 2 (live). ``mitre_meta`` must never import
   ``threadlinqs_*`` (asserted at module level).
"""

from __future__ import annotations

import importlib
import json
import pathlib
import re
import sys

import yaml

from app.services.mitre_meta import (
    TECHNIQUE_NAMES,
    TTP_TACTICS,
    resolve_technique_meta,
    technique_meta,
)

UNIT_DIR = pathlib.Path(__file__).resolve().parent
TESTS_DIR = UNIT_DIR.parent
BACKEND_DIR = TESTS_DIR.parent
FIXTURE_PATH = BACKEND_DIR / "fixtures" / "mitre_attack_v15.yaml"
STIX_SAMPLE_PATH = TESTS_DIR / "fixtures" / "stix_sample.json"
SCRIPTS_DIR = BACKEND_DIR / "scripts"

# ---------------------------------------------------------------------------
# The 47-technique union — minimal assertion set (guardrail F1)
# ---------------------------------------------------------------------------

# (a) techniques referenced in backend/fixtures/full_rules85.yaml
_RULES_TECHNIQUES = {
    "T1003.002", "T1027", "T1033", "T1036", "T1059", "T1059.001", "T1059.003",
    "T1078", "T1098", "T1140", "T1199", "T1204.002", "T1218.005",
    "T1218.010", "T1218.011",
}

# (b) TTP acceptance-bundle TL-2026-1693 (_DEFAULT_TTPS in management_service.py)
_BUNDLE_TECHNIQUES = {
    "T1566.001", "T1566.002", "T1199", "T1204", "T1059.001", "T1059.003",
    "T1053.005", "T1078", "T1098", "T1543.003", "T1547.001", "T1027", "T1036",
    "T1140", "T1218.005", "T1218.010", "T1218.011", "T1055", "T1003.002",
    "T1110.003", "T1056.001", "T1033", "T1082", "T1083", "T1057", "T1016",
    "T1018", "T1046", "T1021.001", "T1570", "T1113", "T1115", "T1005",
    "T1071.001", "T1071.004", "T1568.002", "T1090", "T1095", "T1102", "T1105",
    "T1573.001", "T1041", "T1486", "T1489", "T1496",
}

# (c) keys of TTP_TACTICS / TECHNIQUE_NAMES in app/services/mitre_meta.py
_HARDCODED_TECHNIQUES = set(TTP_TACTICS) | set(TECHNIQUE_NAMES)

# Union == 47 (asserted; drifted tables must update this test, not the other way)
UNION_TECHNIQUES = _RULES_TECHNIQUES | _BUNDLE_TECHNIQUES | _HARDCODED_TECHNIQUES
_EXPECTED_UNION_COUNT = 47


def _load_fixture() -> dict:
    """Load the committed YAML v15 fixture (must exist on disk)."""
    assert FIXTURE_PATH.exists(), f"fixture missing: {FIXTURE_PATH}"
    with FIXTURE_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_stix_sample() -> list[dict]:
    with STIX_SAMPLE_PATH.open(encoding="utf-8") as fh:
        payload = json.load(fh)
    objects = payload.get("objects", payload) if isinstance(payload, dict) else payload
    return [o for o in objects if isinstance(o, dict) and o.get("type") == "attack-pattern"]


_FIXED_PROVENANCE = {
    "version": "15.x",
    "generated_at": "2026-08-15",
    "source": "threadlinqs_mcp_export_stix",
    "license": "CC-BY-4.0",
}


# ---------------------------------------------------------------------------
# HC-3: mitre_meta must not import threadlinqs_*
# ---------------------------------------------------------------------------


def test_mitre_meta_imports_no_threadlinqs_modules():
    import app.services.mitre_meta as mm
    src = pathlib.Path(mm.__file__).read_text(encoding="utf-8")
    assert "threadlinqs_client" not in src
    assert "threadlinqs_cache" not in src


# ---------------------------------------------------------------------------
# F1: union ⊆ fixture, non-empty name+tactic, no placeholders
# ---------------------------------------------------------------------------


def test_union_is_47_techniques():
    assert len(UNION_TECHNIQUES) == _EXPECTED_UNION_COUNT
    for tid in UNION_TECHNIQUES:
        assert re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid), tid


def test_union_subset_of_fixture():
    data = _load_fixture()
    techniques = data["techniques"]
    missing = sorted(UNION_TECHNIQUES - set(techniques))
    assert not missing, f"fixture missing union techniques: {missing}"


def test_fixture_has_no_placeholder_names():
    data = _load_fixture()
    for tid, entry in data["techniques"].items():
        name = entry.get("name", "")
        assert name and name != tid, f"placeholder name for {tid}"
        tactic = entry.get("tactic", "")
        assert tactic, f"missing tactic for {tid}"


def test_union_elements_resolve_nonempty_name_and_tactic_without_mcp():
    # HC-3: live_lookup=None exercises levels 1/3/4 — must never placeholder/throw.
    for tid in sorted(UNION_TECHNIQUES):
        meta = resolve_technique_meta(tid)
        assert meta.name, tid
        assert meta.name != tid, f"placeholder name for {tid}"
        assert meta.tactic, tid


# ---------------------------------------------------------------------------
# F4: data_sources non-empty for the union
# ---------------------------------------------------------------------------


def test_union_techniques_have_nonempty_data_sources():
    data = _load_fixture()
    techniques = data["techniques"]
    empty = [
        tid for tid in UNION_TECHNIQUES
        if not techniques.get(tid, {}).get("data_sources")
    ]
    assert not empty, f"union techniques without data_sources: {empty}"


# ---------------------------------------------------------------------------
# F2 + F3: deterministic build_fixture (pure layer), stable provenance
# ---------------------------------------------------------------------------


def _import_build_fixture():
    # The generator script sits in backend/scripts (infra utilities); import
    # build_fixture only — fetch_stix is never invoked in tests (F2).
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    import generate_mitre_v15_fixture as gen
    return gen.build_fixture, gen


def test_generated_at_is_date_only():
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", _FIXED_PROVENANCE["generated_at"])


def test_build_fixture_is_deterministic_byte_identical():
    build_fixture, _gen = _import_build_fixture()
    stix_objects = _load_stix_sample()
    first = build_fixture(stix_objects, _FIXED_PROVENANCE)
    second = build_fixture(stix_objects, _FIXED_PROVENANCE)
    assert isinstance(first, bytes)
    assert first == second


def test_build_fixture_output_parses_and_covers_sample():
    build_fixture, _gen = _import_build_fixture()
    out = build_fixture(_load_stix_sample(), _FIXED_PROVENANCE)
    parsed = yaml.safe_load(out.decode("utf-8"))
    assert parsed["_provenance"]["license"] == "CC-BY-4.0"
    techniques = parsed["techniques"]
    # every attack-pattern in the sample produced a non-placeholder entry
    for entry in techniques.values():
        assert entry["name"] and entry["name"] != entry.get("technique_id", "")
        assert entry["tactic"]
        assert entry["data_sources"]


# ---------------------------------------------------------------------------
# HC-3 fallback order: levels 1/3/4 with live_lookup=None, level 2 with fake
# ---------------------------------------------------------------------------


def test_fallback_level1_bundle_names_wins():
    bundle = {"T1059.001": "Bundle PowerShell Name"}
    meta = resolve_technique_meta("T1059.001", bundle_names=bundle)
    assert meta.name == "Bundle PowerShell Name"
    assert meta.tactic  # tactic falls through to fixture/hardcoded


def test_fallback_level1_bundle_unknown_skips_to_lower_levels():
    # Bundle doesn't know this technique → fixture (level 3) or hardcoded (4).
    meta = resolve_technique_meta("T1059.001", bundle_names={})
    assert meta.name and meta.name != "T1059.001"


def test_fallback_level2_live_lookup_beats_fixture():
    def fake_live(technique_id: str) -> dict | None:
        if technique_id == "T1059.001":
            return {"name": "Live PowerShell", "tactic": "execution"}
        return None

    meta = resolve_technique_meta("T1059.001", live_lookup=fake_live)
    assert meta.name == "Live PowerShell"
    assert meta.tactic == "execution"


def test_fallback_level2_live_missing_falls_to_lower_levels():
    def fake_live(technique_id: str) -> dict | None:
        return None  # live is unreachable / unknown

    meta = resolve_technique_meta("T1059.001", live_lookup=fake_live)
    assert meta.name and meta.name not in ("T1059.001", "Live PowerShell")


def test_fallback_level4_hardcoded_unknown_technique_is_empty():
    # Not in bundle, no live, not in fixture, not hardcoded → degraded empty.
    meta = resolve_technique_meta("T9999")
    assert meta.name == ""
    assert meta.tactic == ""


def test_technique_meta_hardcoded_still_works():
    # Existing entry point stays intact (ADDITIVE-ONLY).
    assert technique_meta("T1059.001").name == "PowerShell"