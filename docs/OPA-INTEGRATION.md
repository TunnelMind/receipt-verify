# OPA integration — TunnelMind as the PIP

> Moved here 2026-08-02 from `tunnelmind-data-api/docs/OPA-INTEGRATION.md`
> (research-house shift, part 2) so the guide stays publicly readable.

OPA's own docs say it: *"OPA is not designed to be a source of truth."* A PDP
needs a Policy Information Point to answer "who is this node, really?" —
TunnelMind is that PIP: four lenses, one signed, coverage-honest bundle.

Two consumption patterns, matching OPA's External Data guidance:

## Pattern 1 — `http.send` on the decision path (this doc)

Use `GET /v1/attributes/{node}` — the hot-path endpoint. It serves the
last-known signed verify bundle from cache in <100ms (a full
`POST /v1/verify` fans out across the lenses in ~2s; do that in preflight or
out-of-band, not per-request).

```rego
package authz

import rego.v1

default allow := false

tm := http.send({
    "method": "GET",
    "url": sprintf("https://data.tunnelmind.ai/v1/attributes/%s", [input.destination]),
    "headers": {"Authorization": sprintf("Bearer %s", [opa.runtime().env.TUNNELMIND_API_KEY])},
    "cache": true,
    "caching_mode": "deserialized",
}).body

allow if {
    tm.ok
    tm.data.cross_lens.verdict == "pass"
}
```

That's the whole integration. Free API key: `POST /v1/keys/free`.

### Reading the bundle like a PDP should

The bundle carries its own honesty contract (P69):

| Field | Meaning |
|---|---|
| `data.cross_lens.verdict` | `pass` / `warn` / `fail` — the fused verdict |
| `data.cross_lens.trust_score` | 0–1 |
| `data.coverage.rollup` | per-lens tri-state counts: `observed_clean` / `never_observed` / `degraded` — observation vs honest blind spot vs failure |
| `data.coverage.valid_until` | refresh after this instant |
| `data.coverage.stale_if_error` | seconds you may keep using a stale bundle rather than fail closed |
| `data.attributes_meta.freshness` | `fresh` or `stale` — computed for you |
| `data.receipt` | Ed25519-signed receipt; verify offline with `@tunnelmindai/receipt-verify`, prove inclusion via `/v1/receipts/log/proof` |

A stricter policy gates on freshness and coverage, not just the verdict:

```rego
allow if {
    tm.ok
    tm.data.cross_lens.verdict == "pass"
    tm.data.attributes_meta.freshness == "fresh"
    tm.data.coverage.rollup.degraded == 0
}
```

### Misses

`404` means never-verified (or aged past `stale_if_error`). Your policy
decides: fail closed (`default allow := false` already does), or treat
unknown-but-low-risk destinations separately and let something out-of-band
`POST /v1/verify/{node}` so the next decision has a bundle.

## Pattern 2 — replicated data (bundle/snapshot)

For airgapped or ultra-hot loops, OPA prefers data pushed into the store.
Signed corpus snapshots/diffs are PIP-PLAN item P4 (not shipped yet); until
then, Pattern 1 with `http.send` caching is the supported path.

## Cerbos / Cedar

Same endpoint, same JSON — wire it through Cerbos's `http` driver or a Cedar
entity-provider shim. Worked examples are PIP-PLAN P2.
