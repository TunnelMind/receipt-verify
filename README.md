# @tunnelmindai/receipt-verify

> **Part of TunnelMind — the intelligence layer agents call before they trust the internet.**
> Three lenses on one signed corpus: **Scry** (*who is attacking?*) · **Sigil** (*who can you trust?*) · **Tracker Data API** (*who is watching?*).
> This package serves: **the receipt verifier.** Apache-2.0. See [tunnelmind.ai/standards/receipt-format/v1](https://tunnelmind.ai/standards/receipt-format/v1).

Reference TypeScript verifier for the [TunnelMind Receipt Format v1.0](https://tunnelmind.ai/standards/receipt-format/v1). Implements §4 (Verification procedure) end-to-end plus §8 (Revocation) lookups.

## Install

```bash
npm install @tunnelmindai/receipt-verify
```

Zero runtime dependencies. Targets WebCrypto SubtleCrypto + `fetch` — runs on Node ≥18, Cloudflare Workers, Deno, Bun.

## Quickstart

```ts
import { verifyReceipt } from '@tunnelmindai/receipt-verify';

const receipt = await (
  await fetch('https://data.tunnelmind.ai/v1/receipt/generate?receipt=true', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event_type: 'agent.action', payload: { foo: 'bar' } }),
  })
).json();

const result = await verifyReceipt(receipt);

if (result.valid) {
  console.log('✓ verified', result.receipt_id, 'signed by', result.key_id);
} else {
  console.error('rejected:', result.errors);
  console.warn('warnings:', result.warnings);
}
```

## What the verifier checks (per spec §4 + §8)

1. **Version** — `receipt_version === "1.0"` (verifiers MUST reject unknown majors)
2. **Payload hash** — recompute `0x + hex(SHA-256(JCS(payload)))`, compare to `payload_hash`
3. **Key resolution** — `signature.key_id` must be a non-empty string. It is looked up in a key bundle: `opts.keys` if given, else a fetch of `keysUrl` if given, else the pinned bundle `PINNED_KEY_BUNDLE` shipped in `dist/pinned-keys.js`. An unknown `key_id` or a failed bundle fetch is an error. The key must be `active` or `rotated` and the receipt's `timestamp` must fall inside its `[created_at, rotation_after]` window. The receipt's embedded `signature.public_key` is only compared against the bundle key (a mismatch is an error); it is never used to verify
4. **Signature** — reconstruct the signing object (§3 step 2), JCS-canonicalize, verify Ed25519 against the bundle key from step 3
5. **Attestation-strength ceiling** — reject if `receipt.attestation_strength` exceeds the bundle key's declared strength
6. **Revocation** — use `opts.revocations`, else fetch `https://tunnelmind.ai/.well-known/receipt-revocations.json` (a failed fetch is an error):
   - if `signature.key_id` (or the key that actually verified, see `allowKeyMismatch`) is revoked for `compromise`, reject whatever the receipt's timestamp
   - if it is revoked for another reason AND the receipt was signed after `revoked_at`, reject (signed before: warning)
   - if `receipt_id` is in `revoked_receipts`, reject
7. **Chain sanity** — warn (not reject) if `chain.sequence` and `previous_receipt_hash` are inconsistent. Pass `previous` (the prior receipt) to make it a hard check: `previous_receipt_hash` must equal the `0x`-prefixed SHA-256 of the JCS-canonical previous receipt and `sequence` must be its sequence + 1

Checks 1-5 need no network by default: the key bundle is the pinned one unless you pass `keysUrl`. Check 6 fetches the revocation feed unless you pass `revocations`; it can only be turned off with `unsafeSkipRevocations`.

## Offline + pinned modes

### Key pinning

Trust comes only from pinned keys, never from a key the receipt (or log
checkpoint, or cosignature) carries. The pinned keys are:

- the bundle shipped with the package (`PINNED_KEY_BUNDLE` in `dist/pinned-keys.js`), used by default;
- a bundle you pass as `opts.keys` (or fetch from a `keysUrl` you choose);
- for the CLIs: `--keys` (`verify-verdict.mjs`, defaults to the shipped bundle), `--key` (`verify-log.mjs inclusion`), `--log-key` and `--witness-keys` (`verify-verdict.mjs`).

### Pre-fetched feeds

For high-throughput or air-gapped verifiers, pre-fetch the well-known feeds and pass them in:

```ts
import { verifyReceipt, fetchKeyBundle, fetchRevocations } from '@tunnelmindai/receipt-verify';

const [keys, revocations] = await Promise.all([fetchKeyBundle(), fetchRevocations()]);

const result = await verifyReceipt(receipt, { keys, revocations });
```

### Fully offline

`noFetchKeys: true` uses the pinned bundle (or `opts.keys`) and never touches
the network for keys. Revocation still needs a feed: pass one you fetched
earlier.

```ts
const result = await verifyReceipt(receipt, {
  noFetchKeys: true,
  revocations, // pre-fetched RevocationFeed
});
```

`unsafeSkipRevocations: true` turns revocation checking off instead. It is
**unsafe**: a receipt signed by a revoked or compromised key then verifies.

## Rotation-overlap mode

When the issuer rotates a key, both the old and new key are live for ~24h. A receipt may then name one `key_id` while embedding the other key's `public_key`. `allowKeyMismatch` accepts that (with a warning naming both key_ids) only if the embedded `public_key` is another entry in the same bundle that is `active`/`rotated` and whose `[created_at, rotation_after]` window covers the receipt's timestamp; the signature is verified against that bundle entry. It never rescues a `key_id` missing from the bundle, and never accepts a key that is not in the bundle. The revocation check covers both the named `key_id` and the key that actually verified:

```ts
const result = await verifyReceipt(receipt, { allowKeyMismatch: true });
```

## API

### `verifyReceipt(receipt, opts?)`

Main entry point. Returns `Promise<VerifyResult>`:

```ts
interface VerifyResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  receipt_id?: string;
  key_id?: string;
  attestation_strength?: 'self-asserted' | 'software' | 'tee-tpm' | 'silicon-root';
}
```

### `VerifyOptions`

| Option | Default | Purpose |
|---|---|---|
| `keys` | `PINNED_KEY_BUNDLE` | Key bundle to resolve `key_id` against; takes precedence over `keysUrl` |
| `noFetchKeys` | `false` | Never fetch `keysUrl`; fall back to the pinned bundle (or `keys`) |
| `keysUrl` | (none: pinned bundle) | Fetch the key bundle from this URL (e.g., self-hosted issuer); a failed fetch is an error |
| `revocations` | (fetched) | Pre-fetched `RevocationFeed`; offline callers pass this |
| `unsafeSkipRevocations` | `false` | **UNSAFE**: disable revocation checking, so revoked or compromised keys verify |
| `revocationsUrl` | `tunnelmind.ai/.well-known/receipt-revocations.json` | Self-hosted issuer override; a failed fetch is an error |
| `allowKeyMismatch` | `false` | Accept (with a warning) an embedded `public_key` that is another usable entry in the same bundle; see Rotation-overlap mode |
| `previous` | (none) | The prior receipt; makes the chain check hard (hash link + `sequence` + 1) |
| `fetcher` | `globalThis.fetch` | Custom fetch (e.g., for tests) |

### Lower-level exports

`fetchKeyBundle`, `resolveKey`, `clearKeyCache`, `fetchRevocations`, `isKeyRevoked`, `isReceiptRevoked`, `clearRevocationCache`, `canonicalize`, `canonicalizeBytes`, `RECEIPT_VERSION`.

## Verifying receipts you didn't issue

Receipts are designed to be verifiable by anyone — the receipt names its signing key by `key_id`, and the verifier checks the signature against that key in a pinned bundle (the receipt's embedded public key is only compared, never trusted). You don't need credentials, an account, or any prior relationship with the issuer.

That said: the key bundle and revocation feed must come from a source you trust. The defaults are the bundle pinned in this package and the `tunnelmind.ai` revocation feed; for receipts issued by another producer, pass their bundle as `keys` (or point `keysUrl` / `revocationsUrl` at the producer's well-known endpoints).

## Verifying the transparency log (`scripts/verify-log.mjs`)

The offline verifier for the receipt transparency log (RFC 6962 / RFC 9162
algorithms; node builtins only, zero library code):

```
node scripts/verify-log.mjs sth         <sth.json> <public_key_b64>
node scripts/verify-log.mjs inclusion   <proof.json> [sth.json] --key <b64> --receipt <receipt.json>
node scripts/verify-log.mjs consistency <proof.json>
```

`proof.json` / `sth.json` are exactly the `data` objects returned by
`GET data.tunnelmind.ai/v1/receipts/log/{sth,proof,consistency}`.
`inclusion` verifies the STH against the pinned `--key` (never the key the
STH carries) and recomputes the leaf from the `--receipt` bytes.

`docs/OPA-INTEGRATION.md` shows how a PDP consumes the signed bundle.

## Verifying a reconciliation verdict (`scripts/verify-verdict.mjs`)

The standalone offline verifier for Reconciliation Verdict v1.0 receipts —
re-derives the verdict from receipt bytes with no call to TunnelMind
(signature, payload hash, log inclusion, witness cosignatures, verdict
re-derivation):

```
node scripts/verify-verdict.mjs [--keys <bundle.json>] --log-key <b64> \
  --witness-keys <file.json|b64,b64> <receipt.json|->
curl -s https://data.tunnelmind.ai/v1/verdict/<key> \
  | node scripts/verify-verdict.mjs --log-key <b64> --witness-keys <b64,b64> -
```

Only pinned keys are trusted: `--keys` defaults to the bundle shipped in
`dist/pinned-keys.js` (run `npm run build` first), and the checkpoint and
witness checks fail unless `--log-key` / `--witness-keys` pin their keys.

Its pure dependency chain lives in `scripts/verdict-lib/` — those modules
are the spec (the service runs the same code).

## Spec drift

The JCS canonicalizer in `src/jcs.ts` is **bit-identical** to the issuer-side serializers in `scry-server/src/lib/receipt_v1.js` and `tunnelmind-data-api/api/utils/receipt-v1.js`. Any change to one MUST be mirrored across all three. The JCS tests live in `test/verify.test.mjs` (with the shared helpers in `test/_helpers.mjs`); there is no frozen cross-implementation wire vector yet.

## Migrating from 1.x to 2.0.0

2.0.0 closes trust gaps; each item below can turn a receipt that 1.x accepted
into a rejection. See `CHANGELOG.md`.

- **The key is looked up by `key_id` and pinned.** `signature.key_id` is required. The signature is verified against the bundle key (`keys` > `keysUrl` > the shipped `PINNED_KEY_BUNDLE`), which must be active/rotated and inside its validity window. The embedded `public_key` is no longer verified against; a mismatch is an error.
- **A failed key-bundle fetch is an error**, not a warning.
- **`allowKeyMismatch` is narrower**: it only accepts another usable entry of the same bundle, matched by `public_key`.
- **The 1.x option that skipped the revocation fetch is now `unsafeSkipRevocations`** (named for what it does). Offline callers should pass `revocations` instead.
- **A failed revocation-feed fetch is an error.** A key revoked for `compromise` rejects regardless of the receipt's timestamp.
- **The CLIs trust pinned keys only.** `verify-log.mjs inclusion` requires `--key`, `--receipt` and an STH; `verify-verdict.mjs` needs `--log-key` and `--witness-keys` for the checkpoint and witness checks, and verifies the issuer against `--keys` (default: the shipped bundle).
- **JCS rejects lone surrogates** (1.x silently mapped them to U+FFFD); such a payload fails canonicalization.
- **New: `previous` makes a hard chain check** (opt-in): with it, `previous_receipt_hash` and `sequence` mismatches are errors; without it the chain checks stay warnings.

## License

Apache-2.0. The receipt-format spec text itself is CC-BY-4.0 (separately hosted).

## Related

- [`@tunnelmindai/atap`](https://www.npmjs.com/package/@tunnelmindai/atap) — ATAP receipt verifier (different format, complementary use case)
- [`@tunnelmindai/eat`](https://github.com/TunnelMind/atap/tree/main/packages/eat-js) — EAT Profile v0.1 verifier (RFC 9711 alternative serialization of the same claim set)
- [`agent-onboarding.md`](https://tunnelmind.ai/agent-onboarding.md) — the 5-call golden path that uses these receipts end-to-end
