Moved here 2026-08-02 from `tunnelmind-data-api` (`api/roots/{verify-receipt,
reconcile,tier,log}.js`, `api/utils/{jcs,hash}.js`) — the pure dependency
chain of `../verify-verdict.mjs`. Byte-identical except import paths.
These modules are the spec: the service runs the same reconcile() and
Merkle verifier. Drift rule: any change must be mirrored in the private
service copies (and jcs.js additionally stays bit-identical with the
issuer-side serializers — see the top-level README "Spec drift").

Diverges from the service copy (V004, 2026-10-17): `verify-receipt.js`
trusts only pinned keys. `verifyReceipt(receipt, { keys, logKey, witnessKeys })`
verifies the issuer signature against the bundle key for `signature.key_id`
(default: the shipped `dist/pinned-keys.js`, so run `npm run build` first),
the checkpoint signature against `logKey`, and witness cosignatures against
`witnessKeys`. Public keys embedded in the receipt, checkpoint or cosigs are
never used to verify; without `logKey` / `witnessKeys` those checks fail.

Diverges from the service copy (2026-10-19): `jcs.js` refuses a lone
surrogate as `src/jcs.ts` does (V006); the service copy still maps it to
U+FFFD. Both are pinned by `test/vectors/jcs.json` (`test/jcs-vectors.test.mjs`).
