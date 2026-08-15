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

from dataclasses import dataclass

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