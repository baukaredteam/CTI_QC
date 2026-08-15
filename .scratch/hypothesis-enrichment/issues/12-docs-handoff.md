# 12 — Docs and handoff

**Type:** task
**Status:** ready-for-agent
**Blocked by:** 11

**What to build:** The slice's documentation and status handoff: the four
blind-spot marker terms and the MCP enrichment vocabulary enter the CONTEXT.md
glossary, and PROJECT_STATUS.md records the closed tickets, the locked R2
decisions and P1–P6 amendments, and the GATE results in both MCP modes.

**Acceptance criteria:**

- [ ] CONTEXT.md gains the four blind-spot marker terms (`COVERAGE_GAP`,
      `DRL_BLIND`, `FIELD_PARTIAL`, `SYSMON_BLIND` as marker-prefix entries)
      and the MCP enrichment terms (`related_threats`, `adversary_playbooks`,
      `infrastructure_pivots`, `predicted_next_techniques`, basis
      `attack_flow`) — using the existing glossary vocabulary, no synonyms.
- [ ] PROJECT_STATUS.md marks tickets 01–11 closed, records R2-Q1…R2-Q4 and
      P1–P6, and summarizes the GATE results in both `threadlinqs_enabled`
      modes (populated MCP fields vs pass-through), plus the updated CodeGraph
      dependency map.
- [ ] Next-steps section updated: M5 PostgreSQL persistence, full 85+ rulebook
      import, M7 Pivot agent (`get_ioc_blast_radius`), M8/M9 memory + HITL.

**Tests:** documentation review — terms match CONTEXT.md vocabulary exactly;
no code changes.

**ADDITIVE-ONLY:** appended glossary entries and status updates; no existing
documentation sections are rewritten.
