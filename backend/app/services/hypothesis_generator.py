"""M6.4 — deterministic hunt-hypothesis generator.

Turns a threat bundle + a tenant into a persistent ``Hypothesis`` list seeded
from the coverage report's top-priority blind spots. Purely additive, no LLM,
no DB, no network: it reuses the exact M6.1/M6.3 pipeline facts
(normalize → score → analyze → Admiralty) so coverage statuses, priorities
and verdicts are identical to what the summary orchestrator produces.

Chokepoints are harvested from rules attributed to the technique whose custom
fields list ``adversary_control == LOW`` — a durability disadvantage the
defender can turn into a detection advantage.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha1
from typing import Any, Mapping, Sequence

from app.schemas.hypothesis import Hypothesis, HypothesisChokepoint, HypothesisIOC
from app.schemas.management import AdmiraltyOut
from app.services.admiralty import (
    CorroborationEvidence,
    SourceStructure,
    assign as assign_admiralty,
)
from app.services.coverage.analyzer import COVERAGE_GAP, analyze_coverage
from app.services.management_service import (
    BLIND_MARKER_RU,
    GAP_MARKER_RU,
    _STATUS_RU,
)
from app.services.mitre_meta import (
    _telemetry_fields,
    expected_evidence_ru,
    fields_catalog,
    low_control_field_notes,
    low_control_fields,
    technique_meta,
)
from app.services.relevance_scorer import score_threat
from app.services.threadlinqs_normalizer import normalize_bundle

DEFAULT_MAX_HYPOTHESES = 5
# Top-N IOCs attached per hypothesis (small deterministic slice).
TOP_IOC_LIMIT = 5


def _hypothesis_id(threat_id: str, tenant_id: str, technique_id: str) -> str:
    """Deterministic store key from the hypothesis's provenance.

    A fixed id for the same (threat, tenant, technique) triple makes the
    generator byte-identical across runs (hard determinism requirement) and
    gives the scanner a natural dedupe key when re-scanning a bundle.
    """
    seed = "|".join((threat_id, tenant_id, technique_id))
    return sha1(seed.encode("utf-8")).hexdigest()


def _status_ru(status: str) -> str:
    return _STATUS_RU.get(status, status)


def _apply_blind_marker_ru(status: str | None, text: str) -> str:
    """Ticket 03 (R2-Q4): prefix ``expected_evidence_ru`` with the blind-spot
    marker term for the coverage status, formatted ``"{маркер} — {текст}"``.

    Only exact glossary statuses from the coverage analyzer get a marker
    (same exact-key contract as ``_STATUS_RU``): ``COVERED``, unknown and
    malformed statuses pass through unmarked (the status set is never
    guessed). Idempotent — a text already carrying its marker is returned
    unchanged.
    """
    if status is None:
        return text
    marker = BLIND_MARKER_RU.get(str(status))
    if marker is None:
        return text
    prefix = f"{marker} — "
    if text.startswith(prefix):
        return text
    return prefix + text


def _chokepoints_for(
    technique_id: str,
    rules: Sequence[Any],
) -> list[HypothesisChokepoint]:
    """Harvest LOW-adversary-control fields attributed to the technique."""
    chokepoints: list[HypothesisChokepoint] = []
    seen: set[str] = set()
    for rule in rules:
        if technique_id not in (getattr(rule, "mitre_techniques", None) or []):
            continue
        for cf in list(getattr(rule, "custom_fields", None) or []):
            control = str(getattr(cf, "adversary_control", "") or "").upper()
            field = str(getattr(cf, "name", "") or "").strip()
            if control != "LOW" or not field or field in seen:
                continue
            seen.add(field)
            note = str(getattr(cf, "notes", "") or "").strip()
            chokepoints.append(
                HypothesisChokepoint(
                    field=field,
                    note_ru=note or "Поле под контролем атакующего.",
                )
            )
    return chokepoints


def _source_structure(normalized: Any) -> SourceStructure:
    """Letter input: a structured bundle (indicators + MITRE) dominates."""
    has_iocs = bool(getattr(normalized, "iocs", []))
    has_ttps = bool(getattr(normalized, "ttps", []))
    return SourceStructure.STRUCTURED if (has_iocs or has_ttps) else SourceStructure.NARRATIVE_ONLY


def _evidence(normalized: Any, covering: Sequence[str], primary_status: str) -> CorroborationEvidence:
    return CorroborationEvidence(
        ioc_count=len(getattr(normalized, "iocs", []) or []),
        actor_confidence_high=str(getattr(normalized, "actor_confidence", "") or "").lower()
        in {"high", "высокая"},
        sufficiency_high=bool(covering),
        primary_status=primary_status,
    )


def _expected_evidence(technique_id: str, covering: Sequence[str]) -> str:
    if covering:
        return (
            f"Ожидаемые поля/признаки техники {technique_id}; соотносить с правилами: "
            f"{', '.join(covering)}."
        )
    # COVERAGE_GAP: approved derived model — v15 data sources, fields.yaml
    # availability/requires_gpo, adversary playbooks (seam; ticket 08 feeds it).
    return expected_evidence_ru(technique_id)


def _candidate_chokepoints(technique_id: str) -> list[HypothesisChokepoint]:
    """Ticket 05: candidate chokepoints from catalog facts, not covering rules.

    Canonical intersection — the technique's telemetry-template fields ∩ the
    ``fields.yaml`` entries whose adversary control is exact ``LOW`` (every
    entry for a duplicated name must declare LOW; unknown/missing entries
    never qualify). Deterministic in template order, works for COVERAGE_GAP
    hypotheses where no covering rules exist.
    """
    catalog = fields_catalog()
    low_fields = low_control_fields(catalog)
    seen: set[str] = set()
    candidates: list[HypothesisChokepoint] = []
    for field in _telemetry_fields(technique_id):
        if field not in low_fields or field in seen:
            continue
        seen.add(field)
        note = low_control_field_notes(catalog, field)
        candidates.append(
            HypothesisChokepoint(
                field=field,
                note_ru=note or f"Кандидат-точка: поле {field} под контролем атакующего (LOW).",
            )
        )
    return candidates


def _iocs(normalized: Any, limit: int = TOP_IOC_LIMIT) -> list[HypothesisIOC]:
    """Top-N blockable indicators with their verdict as a Russian note."""
    iocs: list[HypothesisIOC] = []
    for raw in list(getattr(normalized, "iocs", []) or [])[:limit]:
        classified = getattr(raw, "classification", None)
        if classified is not None:
            verdict = str(getattr(classified, "verdict", "")).lower()
            reason = str(getattr(classified, "reason", "") or "").strip()
            verdict_ru = {
                "malicious": "вредоносный",
                "legitimate": "легитимный",
                "unknown": "неизвестная классификация",
            }.get(verdict, verdict)
            note = verdict_ru
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


def _threat_summary(normalized: Any, threat_id: str) -> str:
    """Short deterministic Russian summary from bundle facts only."""
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


def _is_placeholder_name(technique_id: str, name: str) -> bool:
    """A ``name`` equal to the technique id is a placeholder, not a real ATT&CK
    name — ignore it so static/live-resolved facts win."""
    return bool(name) and str(name).strip().upper() == str(technique_id).strip().upper()


def _bundle_technique_names(normalized: Any) -> dict[str, str]:
    """technique_id → best-effort name carried by the bundle (not invented)."""
    names: dict[str, str] = {}
    for item in getattr(normalized, "behavioral", []) or []:
        tid = str(getattr(item, "technique_id", "") or "").strip().upper()
        name = str(getattr(item, "technique_name", "") or "").strip()
        if tid and name and not _is_placeholder_name(tid, name) and tid not in names:
            names[tid] = name
    return names


def _data_sources(covering: Sequence[str]) -> list[str]:
    """Deterministic data-source classification for the hypothesis.

    Covered hypotheses inherit the covering detection rules' log sources
    (sorted, deterministic); uncovered ones list the canonical hunt feeds an
    analyst could query. Never invented: all names exist in the catalog.
    """
    if covering:
        return sorted(set(covering))
    return sorted({"windows_event_log", "sysmon", "email_gateway", "proxy_log"})


def _procedure(technique_id: str, covering: Sequence[str]) -> str:
    if covering:
        return f"Детектировать {technique_id} по покрывающим правилам: {', '.join(covering)}."
    return f"Поведение {technique_id} не покрыто — требуется авторство нового покрывающего правила."


def generate_hypotheses(
    *,
    threat_id: str,
    bundle: Mapping[str, Any],
    tenant: Mapping[str, Any],
    rules: Sequence[Any],
    tactic_map: Mapping[str, str] | None = None,
    technique_names: Mapping[str, str] | None = None,
    max_hypotheses: int = DEFAULT_MAX_HYPOTHESES,
    min_relevance: float | None = None,
    now: str | None = None,
) -> list[Hypothesis]:
    """Pure generator: bundle + tenant + rules → ``list[Hypothesis]``.

    Reuses the M6.1/M6.3 pipeline (normalize → score → analyze → Admiralty)
    so every coverage fact and verdict matches what the management summary
    emits for the same threat + tenant. ``now`` is injectable so the pure path
    stays byte-identical across test runs (hard determinism requirement).
    When ``min_relevance`` is set, a threat scoring below the gate yields no
    hypotheses (M6.4 STEP 4: only relevant tenants get hunt hypotheses).

    ``tactic_map`` and ``technique_names`` are additive fact maps for the live
    scanner (bundle + Threadlinqs-resolved metadata). Offline/tests omit them
    and keep the static id/"" fallback.
    """
    normalized = normalize_bundle(dict(bundle))
    threat_map = {
        "name": getattr(normalized, "title", "") or threat_id,
        "ttps": list(getattr(normalized, "ttps", []) or []),
        "iocs": [i.value for i in (getattr(normalized, "iocs", []) or [])],
        "sectors": list(getattr(normalized, "sectors", []) or []),
        "regions": list(getattr(normalized, "regions", []) or []),
        "actor_confidence": getattr(normalized, "actor_confidence", ""),
    }
    tactic_map = dict(tactic_map or {})
    rules_list = list(rules)

    scored = score_threat(
        threat_map,
        tenant,
        rulebook=[
            {
                "rule_id": getattr(rule, "rule_id", ""),
                "enabled": bool(getattr(rule, "enabled", True)),
                "technique_ids": list(getattr(rule, "mitre_techniques", []) or []),
                "required_log_source": str(getattr(rule, "log_source", "") or ""),
            }
            for rule in rules_list
        ],
    )
    report = analyze_coverage(
        {k: v for k, v in threat_map.items() if k != "iocs"},
        tenant,
        [rule.model_dump() if hasattr(rule, "model_dump") else dict(rule) for rule in rules_list],
        tactic_map=tactic_map or None,
    )

    now = now or datetime.now(timezone.utc).isoformat()
    tenant_id = str(tenant.get("name") or tenant.get("id") or "")
    source = _source_structure(normalized)

    if min_relevance is not None and float(getattr(scored, "score", 0.0)) < float(min_relevance):
        return []

    # Ticket 04 (R2-Q3): display-only bonus uses the same canonical high-
    # confidence predicate as the Admiralty evidence path — no new taxonomy.
    actor_confidence_high = str(getattr(normalized, "actor_confidence", "") or "").lower() in {
        "high",
        "высокая",
    }

    hypotheses: list[Hypothesis] = []
    merged_names = {**_bundle_technique_names(normalized), **(technique_names or {})}
    for rec in report.summary.blind_spots[: max_hypotheses]:
        technique_id = str(rec.technique_id)
        covering = list(rec.covering_rule_ids)
        gap = rec.primary_status == COVERAGE_GAP

        code = assign_admiralty(source, _evidence(normalized, covering, rec.primary_status))
        procedure = _procedure(technique_id, covering)
        text = (
            f"{GAP_MARKER_RU} — {procedure}"
            if gap
            else procedure
        )
        tactic = str(tactic_map.get(technique_id) or technique_meta(technique_id).tactic or "")
        technique_name = merged_names.get(technique_id) or technique_meta(technique_id).name or ""

        hypotheses.append(
            Hypothesis(
                id=_hypothesis_id(threat_id, tenant_id, technique_id),
                threat_id=threat_id,
                tenant_id=tenant_id,
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                priority=float(rec.priority),
                confidence_priority_bonus=float(rec.priority) * 1.25 if actor_confidence_high else None,
                zone=str(getattr(scored, "zone", "")),
                status="proposed",
                coverage_status=str(rec.primary_status),
                coverage_status_ru=_status_ru(str(rec.primary_status)),
                covering_rule_ids=covering,
                admiralty=AdmiraltyOut(
                    letter=code.letter,
                    digit=code.digit,
                    rationale_ru=code.rationale_ru,
                ),
                chokepoints=_chokepoints_for(technique_id, rules_list),
                candidate_chokepoints=_candidate_chokepoints(technique_id),
                expected_evidence_ru=_apply_blind_marker_ru(
                    str(rec.primary_status), _expected_evidence(technique_id, covering)
                ),
                text_ru=text,
                threat_title=str(getattr(normalized, "title", "") or threat_id),
                threat_summary=_threat_summary(normalized, threat_id),
                actor=str(getattr(normalized, "actor", "") or ""),
                sectors=list(getattr(normalized, "sectors", []) or []),
                iocs=_iocs(normalized),
                data_sources=_data_sources(covering),
                created_at=now,
                updated_at=now,
            )
        )
    return hypotheses