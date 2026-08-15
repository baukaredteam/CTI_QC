# CONTEXT — AdversaryGraph HERMES extension (domain glossary)

Canonical terms only — no implementation detail, no spec. Add entries as terms are
resolved during grilling.

## Terms

- **Threat bundle** — one live threat record from Threadlinqs (get_threat_bundle).
  Normalized into IOCs (network/file), behavioral indicators (technique tags),
  sectors, regions, ttps, actor + confidence. Facts only; never LLM-authored.

- **Tenant** — one client's detection profile: sector, geo (e.g. KZ), relevance_config
  (weights), drl_matrix (log-source → count), fp_overrides. The "active client" in the
  management slice. Currently inline profiles; M5 persists them.

- **Coverage status** (per technique × tenant) — COVERED | FIELD_PARTIAL | DRL_BLIND |
  SYSMON_BLIND | COVERAGE_GAP. Best (least blind) across covering rules is primary;
  union of the others are secondary flags.

- **Blind spot** — a threat technique that is not COVERED for a tenant. High priority
  blind spots are the seeds of hunt hypotheses.

- **Hypothesis** — a hunt idea anchored on one blind-spot technique in the active
  tenant, carrying an Admiralty confidence code, coverage status, covering rules, and
  copy-ready AQL. Facts from analyzer/normalizer only.

- **Hypothesis status** — the review lifecycle of a persisted hunt hypothesis:
  `proposed` (scanned in, awaiting analyst), `validated` (accepted into the hunt
  workflow), or `rejected` (dismissed). Only the analyst advances `proposed`; the
  frontend issues the transition (gated by the separate `hypothesis:validate`
  permission), the backend persists it and stamps `updated_at`.

- **Hypothesis store** — the M6.4 persistence seam for hunt hypotheses: an
  in-memory dict serialized to `fixtures/hypotheses.json`. Additive; the M5
  migration swaps callers for PostgreSQL rows without changing the CRUD surface.

- **Chokepoint** — a rule whose key field has adversary_control LOW; detection is
  durable. Gives a 1.25 priority bonus.

- **Admiralty code** — NATO-style scoring: source letter + credibility digit.
  Deterministic servicecomputes it; the LLM never assigns letter/digit, it only wraps
  the computed code in Russian prose. (Resolved mapping: letter from source structure,
  digit from corroboration — see ADR-0002.)

- **Copy-ready AQL** — emitted QRadar AQL for a covering rule that passed the regex
  guard and sufficiency check; safe to copy into a Macro/rule.