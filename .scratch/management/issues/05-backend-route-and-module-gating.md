# 05 — Backend route + module gating

**What to build:** A gated HTTP endpoint that answers a real management request: `GET /api/management/summary?threat_id=&tenant_id=` backed by the orchestrator (ticket 04). The endpoint is protected by a new `management` module (feature-flagged, enabled by default off) and by a `management:view` permission, so it is safe to ship incrementally. A thin route-wiring integration test proves the request flows end to end.

**Blocked by:** 04 — Management service orchestrator.

**Status:** ready-for-agent

- [ ] `GET /api/management/summary?threat_id=&tenant_id=` returns the management summary via the orchestrator.
- [ ] The route is gated behind the `management` module; `management_enabled` defaults to false.
- [ ] Access requires the `management:view` permission.
- [ ] A thin integration test exercises the route wiring (auth/module-gated) against the existing test conventions.
- [ ] Additive only — the route module and its registration do not alter existing routers.