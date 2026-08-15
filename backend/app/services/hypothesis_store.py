"""M6.4 — in-memory Hypothesis store with JSON persistence.

Deterministic, additive, no DB: a global dict keyed by hypothesis id, with
``save_to_file()`` / ``load_from_file()`` against ``backend/fixtures/
hypotheses.json``. The M5 seam swaps this module's callers for PostgreSQL
rows without changing the ``add_hypothesis`` / CRUD signature.

Status lifecycle enforced here: only ``proposed`` records may transition to
``validated`` / ``rejected``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from app.schemas.hypothesis import Hypothesis

logger = logging.getLogger(__name__)

# Global in-memory store. Only this module mutates the dict.
_STORE: dict[str, Hypothesis] = {}
_DEFAULT_FILE: Path | None = None

VALID_STATUSES = {"proposed", "validated", "rejected"}
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "proposed": {"validated", "rejected"},
    "validated": set(),
    "rejected": set(),
}


def default_store_path() -> Path:
    """Resolve the canonical JSON file relative to the backend package."""
    path = _DEFAULT_FILE
    if path is None:
        path = Path(__file__).resolve().parents[2] / "fixtures" / "hypotheses.json"
    return path


def add_hypothesis(hypothesis: Hypothesis, *, file_path: Path | None = None) -> Hypothesis:
    """Insert a new hypothesis into the store (id must be unique)."""
    if not hypothesis.id:
        raise ValueError("Hypothesis id must be set before storing")
    if hypothesis.status not in VALID_STATUSES:
        raise ValueError("Unknown hypothesis status: %s" % hypothesis.status)
    if hypothesis.id in _STORE:
        raise ValueError("Hypothesis already in store: %s" % hypothesis.id)
    _STORE[hypothesis.id] = hypothesis
    if file_path is not None:
        save_to_file(file_path)
    return hypothesis


def list_hypotheses(
    *,
    tenant_id: str | None = None,
    status: str | None = None,
    threat_id: str | None = None,
) -> list[Hypothesis]:
    """Return all stored hypotheses, newest first, optionally filtered."""
    rows = list(_STORE.values())
    if tenant_id:
        rows = [r for r in rows if r.tenant_id == tenant_id]
    if status:
        rows = [r for r in rows if r.status == status]
    if threat_id:
        rows = [r for r in rows if r.threat_id == threat_id]
    rows.sort(key=lambda r: (r.created_at, r.id), reverse=True)
    return rows


def get_hypothesis(hypothesis_id: str) -> Hypothesis | None:
    return _STORE.get(hypothesis_id)


def update_status(hypothesis_id: str, new_status: str) -> Hypothesis | None:
    """Transition a hypothesis's status (proposed -> validated/rejected)."""
    row = _STORE.get(hypothesis_id)
    if row is None:
        return None
    if new_status not in VALID_STATUSES:
        raise ValueError("Unknown hypothesis status: %s" % new_status)
    previous = row.status
    allowed = _VALID_TRANSITIONS.get(previous, set())
    if new_status not in allowed:
        raise ValueError(
            "Invalid status transition: %s -> %s" % (previous, new_status)
        )
    _STORE[hypothesis_id] = row.model_copy(
        update={
            "status": new_status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return _STORE[hypothesis_id]


def add_many(hypotheses: Iterable[Hypothesis]) -> int:
    """Bulk-register hypotheses, replacing any existing id (scanner dedupe)."""
    added = 0
    for hypothesis in hypotheses:
        if not hypothesis.id:
            continue
        if hypothesis.id not in _STORE:
            added += 1
        _STORE[hypothesis.id] = hypothesis
    return added


def clear(file_path: Path | None = None) -> None:
    """Drop all in-memory rows (tests only)."""
    _STORE.clear()
    if file_path is not None:
        save_to_file(file_path)


def save_to_file(file_path: str | Path | None = None) -> Path:
    """Serialize the whole store to the JSON fixture (atomic-ish write)."""
    path = Path(file_path) if file_path is not None else default_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [row.model_dump() for row in _STORE.values()]
    data.sort(key=lambda item: item["id"])
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    logger.info("Saved %d hypotheses to %s", len(data), path)
    return path


def load_from_file(file_path: str | Path | None = None) -> int:
    """Populate the store from the JSON file; returns row count loaded."""
    path = Path(file_path) if file_path is not None else default_store_path()
    if not path.exists():
        return 0
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Hypothesis store file must be a JSON list: %s" % path)
    loaded = [Hypothesis.model_validate(item) for item in raw]
    for row in loaded:
        _STORE[row.id] = row
    logger.info("Loaded %d hypotheses from %s", len(loaded), path)
    return len(loaded)