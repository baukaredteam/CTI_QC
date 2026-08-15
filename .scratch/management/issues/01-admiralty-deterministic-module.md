# 01 — Admiralty deterministic module

**What to build:** A pure, deterministic function that assigns a NATO Admiralty source-evaluation to a hypothesized threat technique (`{letter, digit, rationale_ru}`). The letter is derived only from the nature of the underlying source structure (class B/C/D), and the digit only from corroboration level (2–5). Delivered as a testable unit that turns coverage facts into the Admiralty code plus a Russian rationale string. For every hypothesis the code is computed exactly once and is fully reproducible.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] A pure `assign(...)` (or equivalent) returns `{letter, digit, rationale_ru}` given source-structure class and corroboration input.
- [ ] Letter is only B/C/D, set solely from source structure; digit only from corroboration (2–5).
- [ ] The LLM is never consulted and cannot influence the letter or digit.
- [ ] `rationale_ru` is a Russian-language explanation using CONTEXT.md glossary terms.
- [ ] Unit tests pin the deterministic mappings (structure → letter, corroboration → digit) and assert the code shape and Russian output; no LLM in tests.