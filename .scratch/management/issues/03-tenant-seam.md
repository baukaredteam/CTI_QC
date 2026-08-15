# 03 — Tenant seam

**What to build:** An inline tenant seam so coverage is always tenant-correct. It exposes inline profiles for the three sector tenants (finance, energy, critical_infrastructure) plus an `active_tenant_id` setting. Consumers get deterministic list/get/validate behaviour they can drive by tenant context. This is the seam M5 will later swap for DB-backed tenants without changing the service signature.

**Blocked by:** None — can start immediately.

**Status:** ready-for-agent

- [ ] Inline profiles exist for the three sector tenants and are listable.
- [ ] A tenant can be read by id and validated; unknown ids are rejected cleanly.
- [ ] An `active_tenant_id` setting drives the default.
- [ ] The seam is additive — it does not alter existing coverage pipeline code.