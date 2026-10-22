# Architecture

`@tunnelmindai/receipt-verify` is one function, `verifyReceipt()`, plus the
offline CLIs that reuse it. Nothing here issues receipts; the package only
decides whether a receipt someone hands it was signed by a key the caller
trusts and still means what it says.

## Module map

```
src/index.ts        verifyReceipt(): the §4 procedure, steps 1–7, and every public export
src/jcs.ts          RFC 8785 canonicalizer: the bytes signatures and payload_hash cover
src/keys.ts         key bundle: fetch + per-URL cache, resolveKey, keyUsableAt (status + window)
src/revocation.ts   revocation feed: fetch + cache, isKeyRevoked, isReceiptRevoked
src/pinned-keys.ts  the published bundle, shipped so the default path needs no network
scripts/verify-verdict.mjs   CLI: offline Reconciliation Verdict verifier (argv/IO only)
scripts/verdict-lib/         its kernel: verify-receipt.js (5 checks) + reconcile/tier/log/jcs/hash,
                             vendored from the service; verify-receipt.js calls the package for the envelope
scripts/verify-log.mjs       CLI: independent transparency-log verifier (node builtins only, by design)
test/vectors/jcs.json        frozen JCS vectors shared verbatim with tollbooth and atap
```

## Data flow

```
receipt (untrusted JSON)
   │ 1 receipt_version === "1.0"
   │ 2 payload_hash === 0x+sha256(JCS(payload))                       ← jcs.ts
   │ 3 bundle = opts.keys > fetch(opts.keysUrl) > PINNED_KEY_BUNDLE   ← keys.ts / pinned-keys.ts
   │   entry = bundle[signature.key_id]; embedded public_key must equal it;
   │   keyUsableAt(entry, receipt.timestamp)
   │ 4 Ed25519(bundle key, JCS(receipt − payload − signature.value), base64 signature)
   │ 5 attestation_strength ∈ four tiers and ≤ entry.attestation_strength
   │ 6 feed = opts.revocations > fetch(revocationsUrl); key + receipt lookups   ← revocation.ts
   │ 7 chain sanity (warning), or hard hash+sequence link when opts.previous is given
   ▼
VerifyResult { valid: errors.length === 0, errors, warnings, receipt_id, key_id, attestation_strength }
```

A verdict receipt goes through `verdict-lib/verify-receipt.js`: check 1 is
the same `verifyReceipt()` (revocation and ceiling switched off: a verdict
receipt has neither contract), then payload hash, Merkle inclusion against
the checkpoint, witness cosignatures under pinned keys, and `reconcile()`
re-run over the payload and compared with the published verdict.

## Trust boundaries

- **Trusted:** the key bundle (whichever of the three sources the caller
  chose) and the revocation feed. Both are trusted as whole documents; a
  fetched body is validated only for shape (`keys` array; feed arrays
  normalised to `[]`), and a malformed entry makes the receipt fail, never pass.
- **Untrusted:** everything in the receipt, including `signature.public_key`
  (compared to the bundle, never verified against), and every key carried in
  a verdict receipt's checkpoint or cosignatures. CLI file arguments are
  untrusted JSON; a parse failure exits 1.
- **Fail closed:** a failed or malformed fetch, an unparseable timestamp or
  bound, a lone surrogate, a non-base64 signature, an unknown tier — each is
  an error. `valid` is true only with zero errors. Only `unsafe*` options
  widen acceptance, and each is named for what it disables.

## Running the tests

```
npm run build && npm test     # tsc, then node --test test/*.test.mjs (tests import dist/)
```

`test/verify.test.mjs` pins the procedure and its failure modes,
`test/cli.test.mjs` the two CLIs and the kernel, `test/jcs-vectors.test.mjs`
the frozen vectors against all three canonicalizers, and
`test/properties.test.mjs` the invariants (verify(sign(x)), single-bit flips,
canonicalize round-trip and cross-implementation agreement on random input).
