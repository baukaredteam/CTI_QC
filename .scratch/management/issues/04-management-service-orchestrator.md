# 04 — Management service orchestrator

**What to build:** The deterministic orchestrator that turns a threat and a tenant into the «Сводка» (BLUF) plus a priority-sorted list of hunt hypotheses. It reuses the existing coverage pipeline and cache (fetch → normalize → score → analyze over the tenant) to compute per-hypothesis coverage status and covering rules, seeds hypotheses from the top blind spots, and attaches the Admiralty code (ticket 01), the copy-ready AQL bundle (ticket 02), secondary blind flags, chokepoint markers, and — where no rule covers a behavior — the explicit «нет покрывающего правила» gap marker. This is the demoable, fixture-driven heart of the slice.

**Blocked by:** 01 — Admiralty deterministic module, 02 — Mini M4 AQL emitter, 03 — Tenant seam.

**Status:** ready-for-agent

- [ ] Given a `threat_id` (default `TL-2026-1693`) and a `tenant_id`, it returns a summary with a Russian BLUF «Сводка» and priority-sorted hypotheses.
- [ ] Hypotheses are seeded from the priority-sorted top-N coverage report blind spots using coverage facts only.
- [ ] Each hypothesis carries an Admiralty code (from 01), coverage status, covering rules, a copy-ready AQL bundle (from 02), secondary blind flags, and a chokepoint marker.
- [ ] A hypothesis with no covering rule carries the `COVERAGE_GAP` marker rendered as «нет покрывающего правила».
- [ ] Reuses the existing coverage machinery — no duplicate fetch/normalize/score logic; no DB rows introduced.
- [ ] Fixture-driven unit tests run fully offline against the canonical rule fixture; no LLM in tests; the deterministic fallback is what is asserted.