# 06 — Frontend /management page

**What to build:** A demoable `/management` page against the live endpoint (ticket 05). It shows the Russian BLUF «Сводка» and a card per hunt hypothesis carrying the Admiralty code, coverage status, covering rules, and the copy-ready AQL with its flag and warnings. The active tenant is shown and switchable via `?tenant=`, and the threat is selectable via `?threat_id=`. The route is lazy-loaded and gated by the `management` module RoleGate, matching the app's existing navigation/RBAC conventions.

**Blocked by:** 05 — Backend route + module gating.

**Status:** ready-for-agent

- [ ] A `/management` page renders the BLUF «Сводка» and a card per hypothesis from the management endpoint.
- [ ] Each hypothesis card shows the Admiralty code, coverage status, covering rules, and the copy-ready AQL with its `copy_ready`/warnings.
- [ ] A covered behavior lists its covering rule; an uncovered behavior shows «нет покрывающего правила» with the gap marker.
- [ ] Tenant switching via `?tenant=` and threat selection via `?threat_id=` work against the active view.
- [ ] Route is lazy-loaded and gated behind `<RoleGate module="management">` per existing conventions.
- [ ] Additive only — the page and its registration do not alter existing pages or routing.