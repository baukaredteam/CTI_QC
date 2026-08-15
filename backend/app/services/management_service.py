"""Management service orchestrator — M6.3, ticket 04. Deterministic, no LLM.

Turns a threat and a tenant into the Russian «Сводка» (BLUF) plus a
priority-sorted list of hunt hypotheses. Reuses the existing pipeline:
  fetch (cache+client) → normalize → score → analyze
with no duplicate logic and no DB rows. Each hypothesis carries the
Admiralty code (ticket 01), coverage status, covering rules, the copy-ready
AQL bundle (ticket 02), secondary blind flags, and the chokepoint marker.
A hypothesis with no covering rule carries the exact
«нет покрывающего правила» gap marker.

The deterministic path must produce identical bytes offline and live — the
BLUF and hypothesis text are pure templates over pipeline facts.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.schemas.aql import AQLRule
from app.schemas.management import (
    AdmiraltyOut,
    HypothesisChokepoint,
    HypothesisIOC,
    HypothesisOut,
    ManagementSummary,
)
from app.services.admiralty import (
    CorroborationEvidence,
    SourceStructure,
    assign as assign_admiralty,
)
from app.services.bb_resolver import load_shared_bbs, resolve_rule
from app.services.coverage.analyzer import (
    COVERAGE_GAP,
    COVERED,
    analyze_coverage,
)
from app.services.aql_emitter import from_resolved_detection
from app.services.mitre_meta import (
    TTP_TACTICS,
    candidate_fields,
    technique_meta,
)
from app.services.relevance_scorer import score_threat
from app.services.rules_parser import parse_rules_file
from app.services.tenants_provider import active_tenant_id, require_tenant
from app.services.threadlinqs_normalizer import normalize_bundle

logger = logging.getLogger(__name__)

DEFAULT_THREAT_ID = "TL-2026-1693"
DEFAULT_MAX_HYPOTHESES = 5

# Canonical TL-2026-1693 campaign facts (botnet spread / crypto theft), the
# exact 45-TTP campaign the repo plans real rules against (see tests). Used
# to make the default path offline-deterministic when the live Threadlinqs
# integration is unavailable.
_DEFAULT_TTPS = [
    "T1566.001", "T1566.002", "T1199",
    "T1204", "T1059.001", "T1059.003", "T1053.005",
    "T1078", "T1098", "T1543.003", "T1547.001",
    "T1027", "T1036", "T1140", "T1218.005", "T1218.010", "T1218.011", "T1055",
    "T1003.002", "T1110.003", "T1056.001", "T1033", "T1082", "T1083", "T1057",
    "T1016", "T1018", "T1046",
    "T1021.001", "T1570",
    "T1113", "T1115", "T1005",
    "T1071.001", "T1071.004", "T1568.002", "T1090", "T1095", "T1102", "T1105", "T1573.001",
    "T1041",
    "T1486", "T1489", "T1496",
]

# Tactic per technique — canonical campaign mapping mirrored from the M6.1
# acceptance fixture so the offline tactic_coverage matches a live fetch.
# Shared source of truth lives in app.services.mitre_meta; this alias keeps
# the offline bundle builder deterministic with zero duplication.
_DEFAULT_TACTICS = TTP_TACTICS


def _offline_bundle(threat_id: str) -> dict[str, Any]:
    """Deterministic canonical bundle — only for the default threat id.

    Any other id is unknown offline; the caller decides how to surface that.
    """
    if threat_id != DEFAULT_THREAT_ID:
        return {"id": threat_id, "title": "", "sectors": [], "regions": [], "ttps": [], "iocs": []}
    techniques = [
        {"id": t, "tactic": _DEFAULT_TACTICS[t]}
        for t in _DEFAULT_TTPS
        if t in _DEFAULT_TACTICS
    ]
    return {
        "id": DEFAULT_THREAT_ID,
        "title": "Sauri",
        "sectors": ["finance", "cryptocurrency"],
        "regions": ["Global"],
        "ttps": list(_DEFAULT_TTPS),
        "techniques": techniques,
        "iocs": [],
        "actor_confidence": "high",
    }

# The exact gap marker (spec/glossary vocabulary — never a synonym).
GAP_MARKER_RU = "нет покрывающего правила"

# Coverage status → Russian label (CONTEXT.md glossary).
_STATUS_RU: dict[str, str] = {
    "COVERED": "покрыто",
    "FIELD_PARTIAL": "частично покрыто",
    "DRL_BLIND": "не видно источником (DRL ниже порога)",
    "SYSMON_BLIND": "не видно (Sysmon не охвачен)",
    "COVERAGE_GAP": GAP_MARKER_RU,
}

# Ticket 03 (R2-Q4): blind-spot marker terms prefixed onto expected_evidence_ru.
# Exact glossary text — never a synonym; the gap marker reuses GAP_MARKER_RU.
DRL_BLIND_MARKER_RU = "источник не видит событие"
FIELD_PARTIAL_MARKER_RU = "частичное покрытие"
SYSMON_BLIND_MARKER_RU = "Sysmon не охвачен"

BLIND_MARKER_RU: dict[str, str] = {
    "COVERAGE_GAP": GAP_MARKER_RU,
    "DRL_BLIND": DRL_BLIND_MARKER_RU,
    "FIELD_PARTIAL": FIELD_PARTIAL_MARKER_RU,
    "SYSMON_BLIND": SYSMON_BLIND_MARKER_RU,
}


def _fixtures_dir() -> Path:
    """Resolve the backend fixtures directory relative to this module."""
    return Path(__file__).resolve().parents[2] / "fixtures"


def _normalized_threat(bundle: Mapping[str, Any]) -> Any:
    """Normalize a (flattened) raw Threadlinqs bundle into a NormalizedThreat."""
    return normalize_bundle(dict(bundle))


def _scorer_rulebook(rules: Sequence[Any]) -> list[dict[str, Any]]:
    """Project parsed rules into the M1 scorer's expected shape."""
    return [
        {
            "rule_id": r.rule_id,
            "enabled": r.enabled,
            "technique_ids": list(r.mitre_techniques),
            "required_log_source": r.log_source or "",
        }
        for r in rules
    ]


def _analysis_rulebook(rules: Sequence[Any]) -> list[dict[str, Any]]:
    """Project parsed rules into the dict shape analyze_coverage consumes."""
    return [r.model_dump() for r in rules]


def _tactic_map_from_bundle(bundle: Mapping[str, Any]) -> dict[str, str]:
    """Extract technique → tactic from bundle-carried technique lists."""
    if not isinstance(bundle.get("techniques"), list):
        return {}
    tactic_map: dict[str, str] = {}
    for item in bundle["techniques"]:
        if not isinstance(item, Mapping):
            continue
        tid = str(item.get("id") or item.get("technique_id") or "").upper().strip()
        tactic = str(item.get("tactic") or item.get("tactic_name") or "").strip()
        if tid and tactic:
            tactic_map[tid] = tactic
    return tactic_map


def _evidence(
    normalized: Any,
    aql: AQLRule | None,
    primary_status: str,
) -> CorroborationEvidence:
    """Corroboration facts for one hypothesis (ADR-0002)."""
    ioc_count = len(getattr(normalized, "iocs", []) or [])
    actor_confidence = str(getattr(normalized, "actor_confidence", "") or "").lower()
    actor_confidence_high = actor_confidence in {"high", "высокая"}
    sufficiency_high = (
        aql is not None
        and aql.copy_ready
        and aql.sufficiency is not None
        and float(aql.sufficiency.sufficiency_pct) >= 100.0
    )
    return CorroborationEvidence(
        ioc_count=ioc_count,
        actor_confidence_high=actor_confidence_high,
        sufficiency_high=bool(sufficiency_high),
        primary_status=primary_status,
    )


def _source_structure(normalized: Any) -> SourceStructure:
    """Letter input: structured bundle (iocs + MITRE) dominates."""
    has_iocs = bool(getattr(normalized, "iocs", []) or [])
    has_ttps = bool(getattr(normalized, "ttps", []) or [])
    return SourceStructure.STRUCTURED if (has_iocs or has_ttps) else SourceStructure.NARRATIVE_ONLY


def _copy_aql_for_rule(
    rule_id: str,
    rules: Sequence[Any],
    shared_bbs: Mapping[str, dict[str, Any]],
) -> AQLRule | None:
    """Emit the copy-ready AQL for the rule with ``rule_id`` if it exists."""
    for rule in rules:
        if rule.rule_id == rule_id:
            try:
                detection = resolve_rule(rule, dict(shared_bbs))
            except Exception:  # never fail the summary off a single rule
                logger.warning("resolve_rule failed for %s", rule_id, exc_info=True)
                return None
            try:
                return from_resolved_detection(
                    detection,
                    [cf.model_dump() for cf in (rule.custom_fields or [])],
                )
            except Exception:  # never fail the summary off a single rule
                logger.warning("aql emitter failed for %s", rule_id, exc_info=True)
                return None
    return None


def _hypothesis_text(
    technique_id: str,
    status: str,
    covering_rule_ids: Sequence[str],
    admiral_code: str,
) -> str:
    if covering_rule_ids:
        rules_txt = ", ".join(covering_rule_ids)
        return (
            f"Гипотеза {technique_id}: статус «{_STATUS_RU.get(status, status)}»; "
            f"покрытие правилами {rules_txt}. Admiralty: {admiral_code}."
        )
    return (
        f"Гипотеза {technique_id}: {GAP_MARKER_RU}. "
        f"Требуется авторство нового покрывающего правила. Admiralty: {admiral_code}."
    )


def _summary_evidence(technique_id: str, covering_rule_ids: Sequence[str]) -> str:
    """Expected-evidence line echoed by the M6.3 summary (mirrors generator)."""
    if covering_rule_ids:
        return (
            f"Ожидаемые поля/признаки техники {technique_id}; соотносить с правилами: "
            f"{', '.join(covering_rule_ids)}."
        )
    from app.services.mitre_meta import gap_expected_evidence_ru

    template = gap_expected_evidence_ru(technique_id)
    if template:
        return template
    return "Нет покрывающего правила — ожидаемые свидетельства определит аналитик после валидации."


def _candidate_chokepoints(technique_id: str) -> list[HypothesisChokepoint]:
    """Durable attacker-affected semantic fields as candidate chokepoints."""
    return [
        HypothesisChokepoint(
            field=field,
            note_ru=f"Кандидат-точка (устойчивое поле): {field}.",
        )
        for field in candidate_fields(technique_id)
    ]


def _summary_iocs(normalized: Any) -> list[HypothesisIOC]:
    """Top blockable indicators with their verdict as a Russian note."""
    iocs: list[HypothesisIOC] = []
    for raw in list(getattr(normalized, "iocs", []) or [])[:5]:
        classified = getattr(raw, "classification", None)
        if classified is not None:
            verdict = str(getattr(classified, "verdict", "")).lower()
            note = {
                "malicious": "вредоносный",
                "legitimate": "легитимный",
                "unknown": "неизвестная классификация",
            }.get(verdict, verdict)
            reason = str(getattr(classified, "reason", "") or "").strip()
            if reason:
                note = f"{note} — {reason}."
        else:
            note = "Классификация не доступна."
        iocs.append(
            HypothesisIOC(
                ioc_type=str(getattr(raw, "ioc_type", "") or ""),
                value=str(getattr(raw, "value", "") or ""),
                note_ru=note,
            )
        )
    return iocs


def _threat_summary_sm(normalized: Any, threat_id: str) -> str:
    title = str(getattr(normalized, "title", "") or "").strip()
    actor = str(getattr(normalized, "actor", "") or "").strip()
    sectors = ", ".join(getattr(normalized, "sectors", []) or [])
    ttps = len(getattr(normalized, "ttps", []) or [])
    parts = []
    if title:
        parts.append(title)
    if actor:
        parts.append(f"актор: {actor}")
    if sectors:
        parts.append(f"отрасли: {sectors}")
    if ttps:
        parts.append(f"TTP: {ttps}")
    if not parts:
        parts.append(threat_id)
    return "; ".join(parts)[:200]


def _data_sources(covering_rule_ids: Sequence[str]) -> list[str]:
    if covering_rule_ids:
        return sorted(set(covering_rule_ids))
    return sorted({"windows_event_log", "sysmon", "email_gateway", "proxy_log"})


def build_summary(
    threat_id: str,
    bundle: Mapping[str, Any],
    tenant: Mapping[str, Any],
    *,
    rules: Sequence[Any],
    shared_bbs: Mapping[str, dict[str, Any]],
    tactic_map: Mapping[str, str] | None = None,
    technique_names: Mapping[str, str] | None = None,
    max_hypotheses: int = DEFAULT_MAX_HYPOTHESES,
) -> ManagementSummary:
    """Pure deterministic assembler: bundle + tenant → ManagementSummary.

    The only re-used pipeline steps here are the ones tests assert:
    normalize (threadlinqs_normalizer), score (relevance_scorer),
    analyze (coverage.analyzer). No fetch, no cache, no network.
    """
    normalized = _normalized_threat(bundle)
    threat_map = {
        "ttps": list(normalized.ttps),
        "sectors": list(normalized.sectors),
        "regions": list(normalized.regions),
    }
    tactic_map = dict(tactic_map or {}) or _tactic_map_from_bundle(bundle)

    rules_list = list(rules)
    scorer_rules = _scorer_rulebook(rules_list)
    analysis_rules = _analysis_rulebook(rules_list)

    # score → analyze (reuse the existing pipeline over the tenant).
    scored = score_threat(
        dict(threat_map, iocs=[i.value for i in normalized.iocs], actor_confidence=normalized.actor_confidence),
        tenant,
        rulebook=scorer_rules,
    )
    report = analyze_coverage(threat_map, tenant, analysis_rules, tactic_map=tactic_map or None)

    source = _source_structure(normalized)

    hypotheses: list[HypothesisOut] = []
    bundle_tech_names = {
        str(getattr(b, "technique_id", "") or "").strip().upper(): str(
            getattr(b, "technique_name", "") or ""
        ).strip()
        for b in (getattr(normalized, "behavioral", []) or [])
        if getattr(b, "technique_id", None) and getattr(b, "technique_name", "")
    }
    bundle_tech_names = {**bundle_tech_names, **(dict(technique_names or {}))}
    for rec in report.summary.blind_spots[:max_hypotheses]:
        covering_rule_ids = list(rec.covering_rule_ids)
        aql = _copy_aql_for_rule(covering_rule_ids[0], rules_list, shared_bbs) if covering_rule_ids else None

        evidence = _evidence(normalized, aql, rec.primary_status)
        code = assign_admiralty(source, evidence)

        gap = rec.primary_status == COVERAGE_GAP
        technique_id = str(rec.technique_id)
        hypotheses.append(
            HypothesisOut(
                technique_id=technique_id,
                technique_name=bundle_tech_names.get(technique_id) or technique_meta(technique_id).name or "",
                tactic=str(tactic_map.get(technique_id) or technique_meta(technique_id).tactic or ""),
                priority=rec.priority,
                coverage_status=rec.primary_status,
                coverage_status_ru=_STATUS_RU.get(rec.primary_status, rec.primary_status),
                covering_rule_ids=covering_rule_ids,
                copy_ready_aql=aql,
                secondary_blind_flags=sorted(str(f) for f in (rec.secondary_blind_flags or set())),
                is_chokepoint=rec.is_chokepoint,
                admiralty=AdmiraltyOut(
                    letter=code.letter,
                    digit=code.digit,
                    rationale_ru=code.rationale_ru,
                ),
                gap_marker_ru=GAP_MARKER_RU if gap else None,
                text_ru=_hypothesis_text(
                    technique_id,
                    rec.primary_status,
                    covering_rule_ids,
                    f"{code.letter}-{code.digit}",
                ),
                expected_evidence_ru=_summary_evidence(technique_id, covering_rule_ids),
                candidate_chokepoints=_candidate_chokepoints(technique_id),
                iocs=_summary_iocs(normalized),
                threat_title=str(getattr(normalized, "title", "") or threat_id),
                threat_summary=_threat_summary_sm(normalized, threat_id),
                actor=str(getattr(normalized, "actor", "") or ""),
                sectors=list(getattr(normalized, "sectors", []) or []),
                data_sources=_data_sources(covering_rule_ids),
            )
        )

    bluf_ru = _bluf(
        threat_id=threat_id,
        normalized=normalized,
        tenant=tenant,
        scored=scored,
        report=report,
        hypotheses=hypotheses,
    )

    return ManagementSummary(
        threat_id=threat_id,
        title=str(getattr(normalized, "title", "") or threat_id),
        actor=str(getattr(normalized, "actor", "") or ""),
        tenant_id=str(tenant.get("name") or tenant.get("id") or ""),
        tenant_name=str(tenant.get("name") or tenant.get("id") or ""),
        score=scored.score,
        zone=scored.zone,
        status_counts=dict(report.summary.status_counts),
        tactic_coverage=dict(report.summary.tactic_coverage),
        bluf_ru=bluf_ru,
        hypotheses=hypotheses,
    )


def _bluf(
    threat_id: str,
    normalized: Any,
    tenant: Mapping[str, Any],
    scored: Any,
    report: Any,
    hypotheses: list[HypothesisOut],
) -> str:
    counts = report.summary.status_counts
    total = sum(counts.values()) or 0
    covered = counts.get(COVERED, 0)
    blind = len(report.summary.blind_spots)
    top = hypotheses[0] if hypotheses else None
    top_txt = (
        f"{top.technique_id} ({top.coverage_status_ru}, {top.admiralty.letter}-{top.admiralty.digit})"
        if top is not None
        else "нет гипотез"
    )
    title = str(getattr(normalized, "title", "") or threat_id)
    sector = str(tenant.get("sector", ""))
    return (
        f"«Сводка: угроза «{title}» ({threat_id}) для клиента {sector}. "
        f"Релевантность: {scored.score:.0f}% ({scored.zone}). "
        f"Покрытие: {covered}/{total} техник, слепых зон: {blind}. "
        f"Топ-гипотеза: {top_txt}.»"
    )


async def load_raw_bundle(threat_id: str) -> dict[str, Any]:
    """Fetch or fall back to the deterministic offline bundle.

    When the live Threadlinqs integration is disabled, the default threat
    resolves to the canonical offline bundle so the seam stays deterministic
    (identical bytes test and live). Live fetch reuses client + cache.
    """
    from app.core.config import settings

    if settings.threadlinqs_enabled:
        import redis as _redis

        from app.services.threadlinqs_cache import ThreadlinqsCache
        from app.services.threadlinqs_client import ThreadlinqsClient

        client = ThreadlinqsClient(settings.threadlinqs_api_key)
        redis_conn = None
        if settings.redis_url:
            try:
                redis_conn = _redis.asyncio.from_url(settings.redis_url)
            except Exception:  # noqa: BLE001
                redis_conn = None
        cache = ThreadlinqsCache(redis_conn) if redis_conn is not None else None

        if cache is not None:
            cached = await cache.get(threat_id)
            if cached:
                return cached

        bundle: dict[str, Any] = {}
        await client.connect()
        try:
            result = await client.call_tool("get_threat_bundle", {"threat_id": threat_id})
            bundle = _parse_mcp_result(result)
            if not isinstance(bundle, dict):
                from app.services.threadlinqs_client import ThreadlinqsSessionError
                raise ThreadlinqsSessionError("Unexpected bundle result type: %s" % type(bundle))
        finally:
            await client.disconnect()

        if cache is not None:
            await cache.put(threat_id, bundle)
        return bundle

    return dict(_offline_bundle(threat_id))


def _parse_mcp_result(result: Any) -> Any:
    """Parse an MCP call_tool result into a plain object (same as live smoke)."""
    if hasattr(result, "content"):
        contents = result.content
        if isinstance(contents, list) and contents:
            item = contents[0]
            text = getattr(item, "text", None)
            if text is not None:
                try:
                    return json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    return text
            return item
    if isinstance(result, str):
        try:
            return json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return result
    return result


def flatten_bundle(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Merge a raw API envelope {threat, iocs, ...} into a flat dict."""
    flat = dict(bundle.get("threat") if isinstance(bundle.get("threat"), dict) else bundle)
    if "iocs" in bundle and "iocs" not in flat:
        flat["iocs"] = bundle["iocs"]
    return flat


async def summary(
    threat_id: str = DEFAULT_THREAT_ID,
    tenant_id: str | None = None,
    *,
    bundle: Mapping[str, Any] | None = None,
    rules: Sequence[Any] | None = None,
    shared_bbs: Mapping[str, dict[str, Any]] | None = None,
    tactic_map: Mapping[str, str] | None = None,
    max_hypotheses: int = DEFAULT_MAX_HYPOTHESES,
) -> ManagementSummary:
    """The orchestration seam: ``summary(threat_id, tenant_id)``.

    Offline path: pass ``bundle`` to skip the live fetch (fixture-driven
    unit tests exercise only this path). Live path reuses client + cache.
    Rulebook and shared-BBs default to the canonical fixtures.
    """
    tenant_id = tenant_id or active_tenant_id()
    tenant = require_tenant(tenant_id)

    if bundle is None:
        bundle = await load_flat_bundle(threat_id)
    flat = flatten_bundle(bundle)

    if rules is None:
        rules = parse_rules_file(_fixtures_dir() / "full_rules85.yaml").rules
    if shared_bbs is None:
        shared_bbs = load_shared_bbs(_fixtures_dir() / "shared_bbs.yaml")

    return build_summary(
        threat_id=threat_id,
        bundle=flat,
        tenant=tenant,
        rules=rules,
        shared_bbs=shared_bbs,
        tactic_map=tactic_map,
        max_hypotheses=max_hypotheses,
    )


async def load_flat_bundle(threat_id: str) -> dict[str, Any]:
    """Fetch + flatten + cache the live bundle."""
    return flatten_bundle(await load_raw_bundle(threat_id))