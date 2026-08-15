"""Regex guard (M4.1).

Detects degraded regex patterns in rule conditions and reports them as
``EmitterWarning`` instances. The guard NEVER repairs regex; it only detects
and reports. The caller decides what to do with the warnings.

A pattern is considered "degraded" when either:
  (a) ``re.compile(pattern)`` raises ``re.error`` (the regex is invalid), OR
  (b) the pattern starts with a single ``.`` that is NOT followed by ``*`` —
      e.g. ``.\\cmd.exe`` should have been ``.*\\cmd.exe`` (the star was lost
      in transcription). A pattern starting with ``.*`` is NOT degraded.
"""

from __future__ import annotations

import re

from app.schemas.aql import EmitterWarning

# Matches `IMATCHES 'pattern'`, capturing the pattern inside the single quotes.
# The optional double quotes around the field name are not part of the capture.
_IMATCHES_RE = re.compile(r"IMATCHES\s+'([^']*)'", re.IGNORECASE)

# Single-letter regex escapes Python's ``re`` accepts (both engines support
# these). Any other backslash-letter sequence is a Java-only escape that
# QRadar AQL (Java regex) accepts but Python ``re`` rejects as ``bad escape``.
_SAFE_LETTER_ESCAPES = frozenset("abfnrtvxUNdDsSwWbBAZzg")


def _java_tolerant(pattern: str) -> str:
    """Return ``pattern`` with Java-only backslash-letter escapes neutralized.

    QRadar AQL IMATCHES uses Java regex, which accepts escapes Python ``re``
    rejects (``\\c`` control chars, ``\\p`` Unicode properties, ...). Only the
    backslash before such a letter is dropped; Python-valid escapes (``\\d``,
    ``\\s``, ``\\\\.``, ``\\\\\\\\``, ...) and punctuation escapes are kept
    intact so structure is preserved for the structural-invalidity check.
    """
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt == "\\":
                out.append("\\\\")  # escaped backslash — both engines, keep
                i += 2
                continue
            if nxt.isalpha() and nxt not in _SAFE_LETTER_ESCAPES:
                out.append(nxt)  # Java-only letter escape — drop backslash
                i += 2
                continue
            out.append(ch + nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def extract_imatches_patterns(text: str) -> list[str]:
    """Return every pattern inside single quotes that follows an IMATCHES token.

    Multiple IMATCHES clauses in the same string are all returned, in order.
    Returns an empty list when ``text`` contains no IMATCHES clauses.
    """
    if not text:
        return []
    return _IMATCHES_RE.findall(text)


def is_degraded_pattern(pattern: str) -> bool:
    """True iff ``pattern`` is a degraded regex.

    Degraded means either:
      (a) ``re.compile(pattern)`` raises ``re.error`` (invalid regex), OR
      (b) the ``.*`` export-mangling bug: an UNESCAPED dot immediately
          followed by a backslash (the star was lost in transcription),
          e.g. ``.\\cmd.exe`` instead of ``.*\\cmd.exe``.

    Clean by construction: escaped dots (``\\.``), ``.*`` prefixes,
    literal-ish patterns without a dot-backslash pair (``bar``, ``.foo``),
    and ``^foo$`` are NOT degraded by rule (b); they may still be degraded by
    rule (a) if they fail to compile.
    """
    if pattern is None or not str(pattern).strip():
        return False

    # Rule (a): structurally invalid regex. QRadar AQL IMATCHES is Java regex,
    # so Java-only letter escapes (``\c``, ``\p``, ...) must not count as
    # degradation even though Python's ``re`` rejects them. Any OTHER compile
    # failure (unbalanced brackets, dangling operator, trailing backslash) still
    # makes the pattern degrading.
    try:
        re.compile(_java_tolerant(pattern))
    except re.error:
        return True

    # Rule (b): unescaped dot immediately followed by a backslash.
    return bool(re.search(r"(?<!\\)\.\\", pattern))


def guard_conditions(conditions: list[str]) -> list[EmitterWarning]:
    """Scan ``conditions`` for degraded IMATCHES patterns and return warnings.

    - One ``EmitterWarning`` is appended per degraded pattern occurrence.
    - The input ``conditions`` list is never modified (no in-place edits, no
      reordering, no string replacement).
    - Non-degraded patterns produce no warnings.
    """
    warnings: list[EmitterWarning] = []
    if not conditions:
        return warnings

    for condition in conditions:
        if not condition:
            continue
        for pattern in extract_imatches_patterns(condition):
            if not is_degraded_pattern(pattern):
                continue
            warnings.append(
                EmitterWarning(
                    code="REGEX_DEGRADED",
                    severity="warning",
                    pattern=pattern,
                    message=(
                        "IMATCHES pattern is degraded: "
                        f"{pattern!r} (unescaped dot followed by a backslash "
                        "— likely lost '.*' star — or invalid regex)"
                    ),
                )
            )

    return warnings