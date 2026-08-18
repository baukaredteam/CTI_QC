"""Ticket 11 guardrail — smoke_threadlinqs.py must never emit the API key.

Two invariants pin the acceptance criteria of
``.scratch/hypothesis-enrichment/issues/11-acceptance-and-smoke.md``:

1. **Source guard (static, AST-based):** no ``print(...)`` call anywhere in the
   script may reference ``api_key`` in any argument — not ``api_key[:6]``, not
   an f-string ``{api_key...}``, not ``%``-formatting. The configured-path
   output is the fixed marker ``configured=true`` and nothing else.
2. **Behavior guard (no key):** with ``THREADLINQS_API_KEY`` absent from both
   the environment and settings, ``main()`` prints the skip notice and exits 0
   — it never connects, never prints key material, and is CI-safe.

Same convention as ``test_mitre_meta.py``'s module-purity asserts (read source,
assert absent patterns); no network, no MCP spawn, no Redis.
"""

from __future__ import annotations

import asyncio
import ast
import pathlib
import sys

import pytest

BACKEND_DIR = pathlib.Path(__file__).resolve().parents[2]
SMOKE_SCRIPT_PATH = BACKEND_DIR / "scripts" / "smoke_threadlinqs.py"


def _smoke_source() -> str:
    assert SMOKE_SCRIPT_PATH.exists(), f"smoke script missing: {SMOKE_SCRIPT_PATH}"
    return SMOKE_SCRIPT_PATH.read_text(encoding="utf-8")


def _print_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "print"
    ]


def _arg_names(call: ast.Call) -> list[ast.Name]:
    names: list[ast.Name] = []
    for arg in list(call.args) + [kw.value for kw in call.keywords]:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Name):
                names.append(sub)
    return names


# ---------------------------------------------------------------------------
# 1. Static source guard — no print() may reference api_key
# ---------------------------------------------------------------------------


def test_script_has_print_calls_to_guard():
    """Sanity: the script prints things, so the guard is non-vacuous."""
    tree = ast.parse(_smoke_source())
    assert _print_calls(tree), "no print calls found — guard would be vacuous"


def test_no_print_call_references_api_key():
    """Every print argument is AST-scanned: the key must never surface."""
    tree = ast.parse(_smoke_source())
    offenders = []
    for call in _print_calls(tree):
        for name in _arg_names(call):
            if name.id == "api_key":
                offenders.append(call.lineno)
    assert not offenders, f"print() calls referencing api_key at lines: {offenders}"


def test_no_key_prefix_slice_anywhere():
    """The original leak (``api_key[:6]``) must not reappear in any form."""
    src = _smoke_source()
    assert "api_key[:6]" not in src
    assert "api_key[: " not in src
    assert "api_key[:" not in src


def test_configured_path_prints_fixed_marker():
    """The configured-path output is the inert marker, not key material."""
    src = _smoke_source()
    assert 'print("configured=true")' in src


# ---------------------------------------------------------------------------
# 2. Behavior guard — no key configured → skip notice, exit 0
# ---------------------------------------------------------------------------


def _no_key_env(monkeypatch) -> None:
    monkeypatch.delenv("THREADLINQS_API_KEY", raising=False)
    from app.core.config import settings

    monkeypatch.setattr(settings, "threadlinqs_api_key", "")


def test_main_skips_without_key(monkeypatch, capsys):
    """No key → SKIP notice on stdout, SystemExit(0), no key material."""
    _no_key_env(monkeypatch)
    if str(BACKEND_DIR / "scripts") not in sys.path:
        sys.path.insert(0, str(BACKEND_DIR / "scripts"))
    import smoke_threadlinqs as smoke

    with pytest.raises(SystemExit) as exc_info:
        asyncio.run(smoke.main())

    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "SKIP" in out
    assert "configured=true" not in out