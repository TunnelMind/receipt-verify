`scripts/verdict-lib/` is the pure dependency chain of `../verify-verdict.mjs`:
the verdict kernel (`verify-receipt.js`) and the code it re-derives a verdict
with. The files are vendored from the private service, `tunnelmind-data-api`
(`api/roots/{verify-receipt,reconcile,tier,log}.js`, `api/utils/{jcs,hash}.js`).

**Byte-identical to the service except import paths:** `reconcile.js` and the
verifier half of `log.js`. These are the spec — the service runs the same
`reconcile()` and Merkle verifier — so any change to them must be mirrored in
the service copies. `jcs.js` must additionally produce the same bytes as every
issuer-side serializer for every well-formed input; `test/vectors/jcs.json`
pins it (and `src/jcs.ts`, and `../verify-log.mjs`) in `test/jcs-vectors.test.mjs`.

**Deliberate differences from the service copies:**

- `verify-receipt.js` trusts only pinned keys: the issuer signature is
  verified against the bundle key for `signature.key_id` (default: the shipped
  `dist/pinned-keys.js`, so run `npm run build` first), the checkpoint
  signature against `logKey` and witness cosignatures against `witnessKeys`;
  with no `logKey` / `witnessKeys` the bundle's active/rotated entries stand
  in, matched by `key_id`. Keys embedded in the receipt, checkpoint or cosigs
  are never verified against.
- `verify-receipt.js` check 1 is the package's `verifyReceipt()` (dist/index.js)
  and `hash.js` re-exports the package's `bytesToHex` / `sha256HexPrefixed`,
  so the envelope is verified and hashed by one implementation; `b64ToBytes`
  is standard base64 only, as the package's.
- `jcs.js` refuses a lone surrogate, as `src/jcs.ts` does; the service copy
  still maps it to U+FFFD. A verdict receipt carrying one fails here.
- Only what the kernel calls is kept: the service files' HMAC, API-key,
  timing-safe-compare, base64url, checkpoint-builder and tier-cap helpers
  have no caller in this repo and are not vendored.
