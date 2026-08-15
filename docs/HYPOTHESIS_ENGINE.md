# HYPOTHESIS_ENGINE.md — Quarterly Threat-Hunt Hypothesis Loop

> Skeleton doc. Governs the primary product goal per "Locked decisions v2" in
> `docs/CHANGE_PLAN.md`: quarterly (3-month cycle) threat-hunt hypotheses, not one-off alerts.

---

## The Quarterly Loop — Four Stages

The loop must be repeatable and measurable. Each stage is served by EXISTING routers
(additive-only; we do not rewrite them, we add glue and LLM wrappers).

| # | Stage | What happens | Existing router(s) serving it |
|---|-------|--------------|-------------------------------|
| 1 | **Hypothesize** | Generate quarterly hunt hypotheses (e.g. botnet spread) from client sector/geo relevance, coverage blind spots, and chokepoint analysis | `threat_hunting`, `threat_hunting_ai` |
| 2 | **Hunt / RetroHunt** | Run the hypothesis retroactively over historical telemetry (e.g. DNS logs) | `retrohunt` |
| 3 | **Incident** | Positive findings are registered as an incident and investigated; forensics builds the evidence trail | `investigation`, `evidence_graph` |
| 4 | **Report** | Produce the client/executive report closing the quarter (Zeltser CTI brief template) | `export` |

Reference end-to-end success case: quarterly hypothesis (botnet spread) → retro-hunt over
historical DNS logs → incident registered → forensics → client report.

---

## Blind-Spot Types

A hypothesis is worth hunting where detection coverage is weakest. Four blind-spot types:

| Type | Meaning |
|------|---------|
| **Coverage gap** | No enabled rule covers the technique at all |
| **DRL blind** | A rule exists, but the tenant's DRL for the rule's required log source is too low (< 2) — the rule cannot fire in practice |
| **Field partial** | The rule's required fields are only partially available in the tenant's telemetry (availability degraded) |
| **Sysmon blind** | The detection depends on Sysmon-class endpoint telemetry the tenant does not collect |

---

## Priority Formula

Each candidate hypothesis is scored:

```
priority = sector/geo relevance × blind-spot severity × chokepoint bonus
```

- **Sector/geo relevance** — from the tenant's `relevance_config` (client profile): how relevant the threat is to the client's sector and geography.
- **Blind-spot severity** — how badly the technique falls into one of the four blind-spot types above.
- **Chokepoint bonus** — a hypothesis on a chokepoint technique (a rule whose key field has `adversary_control` LOW) receives a confidence bonus, because the detection is durable — the adversary cannot cheaply mutate around it (playingwithpackets chokepoints concept).

---

## What This Doc Does NOT Cover Yet

- Coverage analyzer implementation (M6.1 — not started; do not start until instructed).
- Agent implementations — see `docs/AGENT_SKILLS.md` for the registry the M7/M8 modules will read.
- Attack Simulation / emulation — OUT of scope per Locked decisions v2.
