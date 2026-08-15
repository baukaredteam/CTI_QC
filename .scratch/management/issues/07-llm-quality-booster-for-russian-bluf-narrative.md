# 07 — LLM quality booster for the Russian BLUF narrative

**What to build:** An optional LLM quality booster for the «Сводка» (BLUF) narrative text only. Where present, it improves the prose of the summary written by the orchestrator (ticket 04). It is a post-demo stretch item: the demo-critical path (tickets 01–06) is fully deterministic and offline, so this ticket only improves fidelity when an LLM provider is available. The LLM never assigns Admiralty codes (ADR-0002) and never changes the deterministic facts.

**Blocked by:** 04 — Management service orchestrator.

**Status:** ready-for-agent — NOTE: this is a post-demo stretch item; the demo-critical path is 01–06 and stays fully offline.

- [ ] When a management LLM provider is configured, the «Сводка» narrative may be improved via the existing adapter seam.
- [ ] The deterministic template path remains the fallback when the LLM is disabled or unavailable.
- [ ] The LLM writes narrative prose only; it never assigns letter/digit and never alters coverage facts, covering rules, or the copy-ready AQL.
- [ ] No LLM call appears in any test; the deterministic template path is always what tests assert.

## Comments

- Stretch/post-demo; not required to land the /management demo.