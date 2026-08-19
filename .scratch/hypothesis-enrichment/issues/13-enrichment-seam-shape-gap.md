# 13 — Enrichment seam shape gap (enrich_hypotheses reads empty top-level blocks)

**Type:** task
**Status:** ready-for-human
**Blocked by:** 11.1, 11.2

**What to build:** Fix the enrichment seam so that `enrich_hypotheses` correctly
populates `related_threats`, `adversary_playbooks`, and `infrastructure_pivots`
on persisted Hypothesis rows when the live v7.1.0 envelope carries enrichment
blocks nested under `threat` (non-empty) but top-level blocks are empty lists.

**Root cause:** `enrich_hypotheses` (threadlinqs_mcp_enricher.py) calls
`normalize_bundle` on the raw envelope returned by the second
`get_threat_hunting_bundle` MCP call. `normalize_bundle` reads top-level
`similar_threats`/`simulations`/`infrastructure_pivots` — these are empty
lists in the live v7.1.0 envelope. The nested `threat.similar_threats` (4
items) is correctly flattened by `flatten_bundle` (Ticket 11.2), but
`enrich_hypotheses` doesn't use the flattened version.

**Live evidence (2026-08-19):**
- CALL 1 (bundle_loader): `has_enrichment_keys=True`, top-level values empty.
  `flatten_bundle` correctly promotes: `flat_similar_threats=4`.
- CALL 2 (enrich_hypotheses): same shape. `normalize_bundle` produces
  `playbooks=0, related=0, pivots=0`. Persisted rows: all enrichment=0.
- Classification: B (enrichment keys present but values empty at top level).

**Approach options (owner to decide):**
1. Have `enrich_hypotheses` flatten the raw envelope before normalizing
   (additive, idempotent).
2. Have `normalize_bundle` read from nested `threat` sub-dict blocks
   (wider change, normalizer contract).
3. Flatten the envelope in `_fetch_bundle` before returning it.

**Tests:** regression proof that `enrich_hypotheses` populates enrichment
fields when the raw envelope has nested blocks.

**ADDITIVE-ONLY:** no production behavior change for existing tests.

**Acceptance criteria:**
- [x] `enrich_hypotheses` populates `related_threats`, `adversary_playbooks`,
      `infrastructure_pivots` on persisted rows when the raw envelope has
      nested enrichment blocks.
- [x] Existing tests unchanged.
- [x] Full regression green.
- [ ] Live GATE A shows enrichment populated (pending owner approval).

### Implementation (2026-08-19)

**Fix:** Added `from app.services.management_service import flatten_bundle` to
`threadlinqs_mcp_enricher.py` and changed `_enriched` to flatten the raw
envelope before normalizing: `normalized = normalize_bundle(flatten_bundle(dict(bundle)))`.

This is a one-line production change (plus import). `flatten_bundle` is
idempotent for already-flat bundles, so existing behavior is preserved.

**RED result:** 2 failures in `test_mcp_enricher.py`:
- `test_enrich_hypotheses_flattens_nested_live_envelope_before_normalize`
- `test_enrich_hypotheses_is_idempotent_for_expected_evidence`
4 passed (flat envelope, pass-through, non-mutation, malformed bundle).

**GREEN result:**
- `test_mcp_enricher.py` + `test_flatten_bundle.py`: **62/62**
- Integration `test_feed_scanner.py`: **16/16**
- Full backend: **1201 passed, 11 skipped** (baseline 1195 + 6 new)
- Ruff: **All checks passed**
- `git diff-tree --check`: **clean**

**Live verification:** Pending owner approval (`APPROVE LIVE MCP VERIFICATION
FOR TICKET 11.3`).
