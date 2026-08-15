# ADR-0002 — Deterministic Admiralty attribution

**Status:** Accepted (grill, session 2026-08-07)
**Deciders:** Human + agent, via /grill-with-docs
**Context:** The management slice must show a NATO-style confidence code on each
hypothesis. The constraint "facts never from the LLM" forbids a model from inventing
a letter/digit. But a realistic NATO A·1..6 scale is far too fine for a single
Threadlinqs bundle and would invite arbitrary choices.
**Decision:** A deterministic `admiralty.py` computes a subset of the NATO scale.
The LLM is only used to render Russian narrative around an already-computed code.

- **Letter** from source structure:
  - `B` — structured Threadlinqs bundle (indicators + MITRE present)
  - `C` — narrative-only / single-source extraction
  - `D` — template-derived or uncorroborated
- **Digit** from corroboration:
  - `2` — two or more independent signals (IOC count above threshold AND
    actor_confidence high AND covering-rule sufficiency high)
  - `3` — one strong signal
  - `4` — weak/partial (partial fields or low confidence)
  - `5` — speculative (coverage gap, no corroboration)

Letters A and digits 1/6 are intentionally unreachable from one bundle (A requires
independent-channel corroboration; 1 is first-hand certainty; 6 is unverified rumour).
**Consequences:** Tests can assert `admiralty.pyservice` output deterministically.
Emitting `<letter>-<digit>` as a structured `{letter, digit, rationale_ru}` object
lets the UI render it and lets the suite assert precisely.