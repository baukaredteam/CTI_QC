# AGENT_SKILLS.md — Agent Skills Registry (Skeleton)

> Registry only — agents are NOT implemented yet. This is the registry the M7/M8 modules
> will read. Backs the dedicated Agents tab per "Locked decisions v2" in `docs/CHANGE_PLAN.md`:
> specialized agents with pre-written skills, not one monolithic LLM call.
> Seed skills are mapped from the Feedly CTI Prompt Library zip (human-provided);
> prompts are NOT authored from scratch.

---

## Six Agents

| Agent | Role in the quarterly loop | Skills / source prompt files (Feedly zip unless noted) |
|-------|---------------------------|--------------------------------------------------------|
| **Hypothesis** | Generates quarterly hunt hypotheses (Stage 1: Hypothesize) | `R2-07`, `R2-08`, `R1-04`, `R3-07` |
| **Coverage** | Identifies blind spots (coverage gap, DRL blind, field partial, sysmon blind) feeding hypothesis prioritization | Our `M6.1` (coverage analyzer — not yet built) |
| **Pivot** | Expands one seed IOC into an attacker network (infrastructure pivoting) | `R3-01`, `R1-12`, `ASN-guide`, infrastructure-pivoting article |
| **Detection** | Turns hypotheses/pivot output into detections (AQL emit path) | `R2-06`, `R3-05`, `R3-06` plus our `M4` (AQL emitter + guardrails) |
| **Triage** | Assesses hunt/retro-hunt hits, supports incident registration (Stage 3: Incident) | `R4-01`, `R4-02` |
| **Reporting** | Produces the client/executive quarterly report (Stage 4: Report) | `R4-08` plus Zeltser CTI brief template |

---

## Pivot Agent — Threadlinqs Reuse Note

The Pivot agent reuses the live Threadlinqs M1 client (no new transport) via these tools:

- `get_ioc_intelligence`
- `get_ioc_blast_radius`
- `get_infrastructure_pivots`
- `get_ioc_dns`

plus ASN enrichment, to expand one seed IOC into an attacker network.

---

## Status

- Agents are NOT implemented. Do not implement from this doc alone.
- This registry is the contract that M7 (agent runtime / skills loading) and M8 (Agents
  page/tab) will read.
- Skill prompt content is sourced by mapping the listed files from the Feedly CTI Prompt
  Library zip; do not author prompts from scratch.
