# 02 — Mini M4 AQL emitter

**What to build:** A minimal AQL emitter, `from_resolved_detection → emit`, that turns a resolved detection into a copy-ready AQL query. It anchors to the LAST window, applies the logsource filter, orders clauses indexed-first using the canonical indexed fields, runs a sufficiency check, guards regexes, and yields `{aql, copy_ready, warnings, sufficiency}`. The key guarantee an analyst gets: a paste-ready query with an explicit `copy_ready` flag and human-readable warnings when it is not safe to paste. The sigma-ast adapter and the fp_injector are explicitly out of scope for this slice (ADR-0001).

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] `emit` over a resolved detection yields an AQL string with a LAST-window anchor and a logsource filter.
- [ ] Fields are ordered indexed-first, driven by the indexed-fields list.
- [ ] A sufficiency check runs and its result is exposed in the bundle.
- [ ] `regex_guard` is applied; its findings are surfaced as warnings.
- [ ] Output is `{aql, copy_ready, warnings, sufficiency}`; `copy_ready` is true only when safe.
- [ ] Field availability is joined from the rule's own `custom_fields`, not from a separate fields file.
- [ ] No sigma-ast adapter and no fp_injector (ADR-0001); unit tests cover the deterministic path only.