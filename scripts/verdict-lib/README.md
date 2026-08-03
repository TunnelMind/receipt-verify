Moved here 2026-08-02 from `tunnelmind-data-api` (`api/roots/{verify-receipt,
reconcile,tier,log}.js`, `api/utils/{jcs,hash}.js`) — the pure dependency
chain of `../verify-verdict.mjs`. Byte-identical except import paths.
These modules are the spec: the service runs the same reconcile() and
Merkle verifier. Drift rule: any change must be mirrored in the private
service copies (and jcs.js additionally stays bit-identical with the
issuer-side serializers — see the top-level README "Spec drift").
