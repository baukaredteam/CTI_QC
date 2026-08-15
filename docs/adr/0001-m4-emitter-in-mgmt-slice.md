# ADR-0001 — M4 AQL emitter scoped into the management slice

**Status:** Accepted (Decision: grill, session 2026-08-07)
**Context:** The handoff lists "M4 AQL emitter + fp_injector partial" but no
`aql_emitter.py` or `fp_injector.py` exists on disk — only `regex_guard.py` and
`schemas/aql.py` (`AQLRule`, `EmitterWarning`, `SufficiencyResult`). The management
demo's hard deliverable is "copy-ready AQL per hypothesis", which has no source.
**Decision:** Build a minimal-but-real M4 emitter in the management slice, fed from
the chosen (best) rule's M3 `resolved_detection`. Scope boundary:

- **In scope now:** `from_resolved_detection -> emit`, with the LAST-window anchor,
  explicit logsource filter, indexed-first ordering (`INDEXED_FIELDS`),
  sufficiency check, and a `regex_guard` pass setting `copy_ready` + warnings.
- **Out of scope for the demo, documented:** the `from_sigma_ast` input adapter and
  the `fp_injector`. Documented in the emitter docstring and CHANGE_PLAN.

**Consequences:** Delivers honest copy-ready AQL (the demo's deliverable) without
overbuilding sigma-ast or FP injection now. ACOVERAGE_GAP (no covering rule) shows
«нет покрывающего правила» instead of a dead AQL; FIELD_PARTIAL/SYSMON_BLIND keep
their warnings in `copy_ready_aql.warnings` so the analyst sees why it is partial.