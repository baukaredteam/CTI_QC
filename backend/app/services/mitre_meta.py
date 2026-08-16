"""M6.4 shared MITRE ATT&CK metadata and telemetry templates.

One deterministic, offline source for the technique-level context the hunt
hypothesis feed and the management summary both emit:
- tactic per technique (moved here from the old test-local map so the
  acceptance test and the live scan read one shared table),
- best-effort ATT&CK technique names (facts, never invented),
- per-technique telemetry: the evidence fields to look for (indexed + real
  QRadar semantic fields) and the candidate chokepoint fields (durable,
  attacker-affected semantic columns).

Facts come only from the ATT&CK table and ``fixtures/fields.yaml`` catalog;
no network, no LLM. Unknown techniques degrade to empty/``""`` values so
calling code stays deterministic.
"""

from __future__ import annotations

import functools
import pathlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Tactic per technique — shared by the analyzer acceptance test and the scan
# ---------------------------------------------------------------------------

TTP_TACTICS: dict[str, str] = {
    "T1566.001": "initial-access", "T1566.002": "initial-access", "T1199": "initial-access",
    "T1204": "execution", "T1059.001": "execution", "T1059.003": "execution", "T1053.005": "execution",
    "T1078": "persistence", "T1098": "persistence", "T1543.003": "persistence", "T1547.001": "persistence",
    "T1027": "defense-evasion", "T1036": "defense-evasion", "T1140": "defense-evasion",
    "T1218.005": "defense-evasion", "T1218.010": "defense-evasion", "T1218.011": "defense-evasion",
    "T1055": "defense-evasion",
    "T1003.002": "credential-access", "T1110.003": "credential-access", "T1056.001": "credential-access",
    "T1033": "discovery", "T1082": "discovery", "T1083": "discovery", "T1057": "discovery",
    "T1016": "discovery", "T1018": "discovery", "T1046": "discovery",
    "T1021.001": "lateral-movement", "T1570": "lateral-movement",
    "T1113": "collection", "T1115": "collection", "T1005": "collection",
    "T1071.001": "command-and-control", "T1071.004": "command-and-control",
    "T1568.002": "command-and-control", "T1090": "command-and-control", "T1095": "command-and-control",
    "T1102": "command-and-control", "T1105": "command-and-control", "T1573.001": "command-and-control",
    "T1041": "exfiltration",
    "T1486": "impact", "T1489": "impact", "T1496": "impact",
}

# ---------------------------------------------------------------------------
# Best-effort ATT&CK technique names (empty when not curated)
# ---------------------------------------------------------------------------

TECHNIQUE_NAMES: dict[str, str] = {
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1204": "User Execution",
    "T1059.001": "PowerShell",
    "T1059.003": "Command Shell",
    "T1053.005": "Scheduled Task",
    "T1078": "Valid Accounts",
    "T1543.003": "Windows Service",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1218.005": "Mshta",
    "T1218.010": "Regsvr32",
    "T1055": "Process Injection",
    "T1003.002": "Security Account Manager Thief",
    "T1110.003": "Password Spraying",
    "T1056.001": "Keylog",
    "T1033": "System Owner/User Discovery",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1057": "Process Discovery",
    "T1016": "Network Configuration Discovery",
    "T1018": "Remote System Discovery",
    "T1046": "Network Service Scanning",
    "T1021.001": "Remote Desktop Protocol",
    "T1570": "Lateral Tool Transfer",
    "T1113": "Screen Capture",
    "T1115": "Clipboard Data",
    "T1005": "Data from Local System",
    "T1041": "Exfiltration Over C2 Channel",
}


@dataclass(frozen=True)
class TechniqueMeta:
    """Resolved metadata for one technique (deterministic)."""

    tactic: str
    name: str


# ---------------------------------------------------------------------------
# Telemetry templates — real field names from the QRadar catalog
# ---------------------------------------------------------------------------

# Real custom (semantic, attacker-affected) fields from fields.yaml. These are
# the durable LOW-control columns an analyst can lean on as chokepoints.
_CANDIDATE_FIELDS: frozenset[str] = frozenset({
    "proc_cmdline",
    "proc_file_path",
    "proc_id",
    "proc_thread_id",
    "proc_usr_sid",
    "event_description",
    "orig_message",
    "child_cmdline",
    "task_id",
    "task_name",
    "file_size",
    "url_full",
    "script_text",
    "cmdline",
    "logon_type",
    "net_src_ipv4",
    "net_dst_port",
    "dns_rname",
    "dns_rdata",
    "dev_hostname",
    "dev_ipv4",
    "event_id",
})

# Log sources a hunt for the technique looks at.
_LOG_SOURCES: frozenset[str] = frozenset({
    "windows_event_log",
    "sysmon",
    "proxy_log",
    "email_gateway",
    "dns_log",
})

# tactic → telemetry bases (indexed-first + semantic evidence fields).
_TACTIC_TELEMETRY: dict[str, tuple[str, ...]] = {
    "initial-access": ("url_full", "email_sender", "attachment_name", "dns_rname"),
    "execution": ("proc_cmdline", "child_cmdline", "script_name", "cmdline"),
    "persistence": ("proc_file_path", "task_name", "registry_path", "logon_type"),
    "defense-evasion": ("proc_cmdline", "proc_file_path", "script_name", "orig_message"),
    "credential-access": ("proc_cmdline", "logon_type", "usr_tgt_name", "event_reason_code"),
    "discovery": ("proc_id", "net_dst_port", "dns_rname", "dev_ipv4"),
    "lateral-movement": ("net_src_ipv4", "net_dst_port", "dev_hostname", "logeventip"),
    "collection": ("file_size", "proc_id", "orig_message", "clipboard_text"),
    "command-and-control": ("dns_rname", "dns_rdata", "net_dst_port", "url_full"),
    "exfiltration": ("net_bytes_sent", "net_dst_port", "url_full", "fileName"),
    "impact": ("file_size", "file_modified_time", "proc_cmdline", "orig_message"),
}

# technique → override for the most common hunts (deterministic real fields).
_TECHNIQUE_TELEMETRY: dict[str, tuple[str, ...]] = {
    "T1059.001": ("proc_cmdline", "child_cmdline", "script_name", "cmdline"),
    "T1082": ("proc_cmdline", "outlook_log", "dispenser", "dev_ipv4"),
    "T1021.001": ("net_src_ipv4", "net_dst_port", "logon_type", "dev_hostname"),
    "T1046": ("net_src_ipv4", "net_dst_port", "scanner_version"),
    "T1486": ("file_size", "file_suffix", "proc_file_path", "orig_message"),
}


def technique_meta(technique_id: str) -> TechniqueMeta:
    """Resolve (tactic, name) for a technique; empty on unknown. Pure."""
    tid = str(technique_id).strip().upper()
    return TechniqueMeta(
        tactic=TTP_TACTICS.get(tid, ""),
        name=TECHNIQUE_NAMES.get(tid, ""),
    )


def _telemetry_fields(technique_id: str) -> tuple[str, ...]:
    tid = str(technique_id).strip().upper()
    if tid in _TECHNIQUE_TELEMETRY:
        return _TECHNIQUE_TELEMETRY[tid]
    tactic = TTP_TACTICS.get(tid, "")
    return tuple(_TACTIC_TELEMETRY.get(tactic, ("proc_cmdline", "dns_rname")))


def evidence_fields(technique_id: str) -> tuple[str, ...]:
    """Telemetry evidence columns to correlate for the technique."""
    indexed = ("qid", "eventid")
    return indexed + tuple(
        f for f in _telemetry_fields(technique_id) if f in _CANDIDATE_FIELDS
    )


def candidate_fields(technique_id: str) -> tuple[str, ...]:
    """Durable attacker-affected semantic fields usable as chokepoints."""
    return tuple(
        f
        for f in _telemetry_fields(technique_id)
        if f in _CANDIDATE_FIELDS and f not in {"qid", "eventid"}
    )


def gap_expected_evidence_ru(technique_id: str) -> str:
    """Russian expected-evidence statement for an uncovered (COVERAGE_GAP)
    technique: names the technique, its tactic and the telemetry fields."""
    meta = technique_meta(technique_id)
    tactic = meta.tactic or "tactic unknown"
    name = meta.name or technique_id
    fields = ", ".join(evidence_fields(technique_id)) or "unavailable"
    return (
        f"Ожидаемые свидетельства техники {technique_id} ({name}, тактика «{tactic}»): "
        f"корреляция в телеметрии по полям {fields}. "
        f"Требуется авторство нового покрывающего правила."
    )


# Alias used by the live-scan smoke helper.
TTP_NAMES = TECHNIQUE_NAMES


# ---------------------------------------------------------------------------
# Ticket 03: approved expected-evidence derivation
# ---------------------------------------------------------------------------
# Expected evidence is derived from: MITRE v15 data sources × fields.yaml
# availability × requires_gpo × adversary playbooks (optional seam, fed by the
# MCP enrichment of ticket 08). Never from a hardcoded candidate-field list.

_FIELDS_YAML_PATH = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "fields.yaml"


@functools.lru_cache(maxsize=1)
def fields_catalog() -> dict[str, dict[str, Any]]:
    """Real fields.yaml facts per field name: availability + requires_gpo.

    Absence of a field means "unknown", never "false". Empty when the fixture
    is missing or unparseable (offline degradation stays deterministic).
    """
    try:
        with _FIELDS_YAML_PATH.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return parse_fields_catalog(data if isinstance(data, dict) else {})


# Explicit token policy for untrusted raw boolean values — unknown input is
# never truthy (mirrors the module's silent-degradation style).
_BOOL_TOKENS_TRUE: frozenset[str] = frozenset({"true", "yes", "1", "on"})
_BOOL_TOKENS_FALSE: frozenset[str] = frozenset({"false", "no", "0", "off"})


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Pure, deterministic coercion of a raw untrusted value to bool.

    A native bool is preserved; a string is matched (strip, case-insensitive)
    against the explicit token set — ``{true, yes, 1, on}`` → True,
    ``{false, no, 0, off}`` or empty/whitespace → False; ``None`` or any
    unknown raw value/type falls back to ``default`` and is never truthy.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _BOOL_TOKENS_TRUE:
            return True
        if token == "" or token in _BOOL_TOKENS_FALSE:
            return False
        return default
    return default


def parse_fields_catalog(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Pure, deterministic parse of ``custom_fields`` into per-name facts.

    Duplicate names merge: availabilities union, ``requires_gpo`` OR-combined,
    adversary controls union, first non-empty note wins. Raw values are treated
    as untrusted QRadar data — stored inert, canonicalized here once with the
    project's existing strip+upper normalization.
    """
    entries: dict[str, dict[str, Any]] = {}
    for cf in data.get("custom_fields") or []:
        if not isinstance(cf, dict):
            continue
        name = str(cf.get("name") or "").strip()
        if not name:
            continue
        availability = str(cf.get("availability") or "").strip().lower()
        requires_gpo = _coerce_bool(cf.get("requires_gpo", False))
        control = str(cf.get("adversary_control") or "").strip().upper()
        notes = str(cf.get("notes") or "").strip()
        existing = entries.get(name)
        if existing is None:
            availabilities: set[str] = {availability} if availability else set()
            entries[name] = {
                "availability": availability,
                "availabilities": availabilities,
                "requires_gpo": requires_gpo,
                "adversary_controls": {control} if control else set(),
                "notes": notes,
            }
        else:
            if availability:
                existing["availabilities"].add(availability)
                if availability != "full" or not existing["availability"]:
                    existing["availability"] = availability
            existing["requires_gpo"] = existing["requires_gpo"] or requires_gpo
            if control:
                existing["adversary_controls"].add(control)
            if notes and not existing["notes"]:
                existing["notes"] = notes
    return entries


# Canonical exact LOW test: a field qualifies only when every catalog entry
# for it declares LOW — an ambiguous/contradictory control is never LOW.
_FIELD_CONTROL_LOW: frozenset[str] = frozenset({"LOW"})


def low_control_fields(catalog: dict[str, dict[str, Any]]) -> set[str]:
    return {
        name
        for name, entry in catalog.items()
        if entry.get("adversary_controls") == _FIELD_CONTROL_LOW
    }


def low_control_field_notes(catalog: dict[str, dict[str, Any]], field: str) -> str:
    """Catalog note for a field ("" when absent) — inert untrusted data."""
    return str((catalog.get(field) or {}).get("notes") or "")


def expected_evidence_ru(
    technique_id: str,
    adversary_playbooks: Sequence[str] = (),
) -> str:
    """Russian expected-evidence statement for an uncovered (COVERAGE_GAP)
    technique, derived from the approved model.

    Dimensions, in order (each only surfaces when the data is actually
    available — absence never invents facts):
    1. MITRE v15 ``data_sources`` from the offline fixture;
    2. the technique's telemetry fields crossed with fields.yaml entries:
       fields whose availability is not ``full`` are flagged partial; fields
       with ``requires_gpo`` carry the GPO configuration note;
    3. ``adversary_playbooks`` — enrichment seam, empty until ticket 08 feeds
       it (no playbooks provided ≠ "there are none").
    """
    meta = technique_meta(technique_id)
    tactic = meta.tactic or "tactic unknown"
    name = meta.name or technique_id
    tid = str(technique_id).strip().upper()

    parts = [f"Ожидаемые свидетельства техники {tid} ({name}, тактика «{tactic}»)"]

    catalog = fields_catalog()
    gpo_fields = sorted(
        f for f in _telemetry_fields(tid) if f in catalog and catalog[f].get("requires_gpo")
    )
    partial_fields = sorted(
        f for f in _telemetry_fields(tid)
        if f in catalog
        and not catalog[f].get("requires_gpo")
        and catalog[f].get("availability") not in ("", "full")
    )
    known_fields = sorted(
        f for f in _telemetry_fields(tid)
        if f in catalog
        and not catalog[f].get("requires_gpo")
        and catalog[f].get("availability") == "full"
    )
    unknown_fields = sorted(f for f in _telemetry_fields(tid) if f not in catalog)

    if known_fields:
        parts.append(f"корреляция в телеметрии по полям {', '.join(known_fields)}")
    if partial_fields:
        parts.append(
            f"поля с частичной доступностью (availability ≠ full): {', '.join(partial_fields)}"
        )
    if gpo_fields:
        parts.append(
            "поля, требующие настройки GPO (при отсутствии GPO поле может быть пустым): "
            + ", ".join(gpo_fields)
        )
    if unknown_fields:
        parts.append(f"каталог полей не подтверждает: {', '.join(unknown_fields)}")

    data_sources = [str(s).strip() for s in (fixture_technique(tid).get("data_sources") or []) if str(s).strip()]
    if data_sources:
        parts.append(f"ATT&CK data sources: {', '.join(data_sources)}")
    else:
        parts.append("ATT&CK data sources для техники в каталоге отсутствуют")

    playbooks = [str(p).strip() for p in (adversary_playbooks or []) if str(p).strip()]
    if playbooks:
        parts.append(f"adversary playbooks: {', '.join(playbooks)}")
    else:
        parts.append("adversary playbooks не переданы — обогащение недоступно")

    return "; ".join(parts) + ". Требуется авторство нового покрывающего правила."


# ---------------------------------------------------------------------------
# Ticket 01: MITRE ATT&CK v15 offline fixture loader + four-level fallback
# ---------------------------------------------------------------------------
# HC-3: this module imports no Threadlinqs client/cache modules and makes no
# network calls. The live level (2) is *injected* by the caller as a callable;
# with live_lookup=None the levels 1/3/4 still work.

_FIXTURE_PATH = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "mitre_attack_v15.yaml"


@functools.lru_cache(maxsize=1)
def _load_v15_fixture() -> dict[str, dict]:
    """Load the committed v15 fixture once; empty dict when missing/broken."""
    try:
        with _FIXTURE_PATH.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return {}
    techniques = data.get("techniques") or {}
    return {k: v for k, v in techniques.items() if isinstance(v, dict)}


def fixture_technique(technique_id: str) -> dict:
    """Offline v15 triple {name, tactic, data_sources[]}; empty on unknown."""
    return _load_v15_fixture().get(str(technique_id).strip().upper(), {})


def resolve_technique_meta(
    technique_id: str,
    bundle_names: dict[str, str] | None = None,
    live_lookup: Callable[[str], dict | None] | None = None,
) -> TechniqueMeta:
    """Four-level fallback resolution for (tactic, name); deterministic, pure.

    Level 1 — bundle_names: accepted-bundle technique names (highest).
    Level 2 — live_lookup: injected callable returning an optional
        {name, tactic} dict (MCP live + 7-day cache); ``None`` skips it.
    Level 3 — committed ``fixtures/mitre_attack_v15.yaml`` (offline).
    Level 4 — hardcoded ``TTP_TACTICS``/``TECHNIQUE_NAMES`` (last resort).

    Unknown techniques degrade to empty values, never a placeholder
    (``name == id``) and never an exception.
    """
    tid = str(technique_id).strip().upper()
    if not tid:
        return TechniqueMeta(tactic="", name="")

    name = ""
    tactic = ""

    # Level 1: bundle names
    if bundle_names and tid in bundle_names:
        name = str(bundle_names[tid]).strip()

    # Level 2: injected live lookup (caller wires client + cache)
    if live_lookup is not None and not name:
        try:
            live = live_lookup(tid) or {}
        except Exception:
            live = {}
        if isinstance(live, dict) and live.get("name"):
            name = str(live["name"]).strip()
            if live.get("tactic"):
                tactic = str(live["tactic"]).strip()

    # Level 3: offline v15 fixture (fills name and/or tactic)
    fixture = fixture_technique(tid)
    if fixture:
        if not name and fixture.get("name"):
            name = str(fixture["name"]).strip()
        if not tactic and fixture.get("tactic"):
            tactic = str(fixture["tactic"]).strip()

    # Level 4: hardcoded tables
    if not name:
        name = TECHNIQUE_NAMES.get(tid, "")
    if not tactic:
        tactic = TTP_TACTICS.get(tid, "")

    return TechniqueMeta(tactic=tactic, name=name)