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
3. **Signature** — reconstruct the signing object (§3 step 2), JCS-canonicalize, verify Ed25519 against the embedded `signature.public_key`
4. **Key bundle resolution** — fetch `https://tunnelmind.ai/.well-known/receipt-signing-key.json`, confirm the resolved key's `public_key` matches the receipt's
5. **Attestation-strength ceiling** — reject if `receipt.attestation_strength` exceeds the resolved key's declared strength
6. **Revocation** — fetch `https://tunnelmind.ai/.well-known/receipt-revocations.json`:
   - if `signature.key_id` is revoked AND the receipt was signed after `revoked_at`, reject
   - if `receipt_id` is in `revoked_receipts`, reject
7. **Chain sanity** — warn (not reject) if `chain.sequence` and `previous_receipt_hash` are inconsistent

The first 3 checks are pure-crypto and require no network. Checks 4-6 fetch well-known feeds, which can be disabled or pre-loaded.

## Offline + pinned modes

For high-throughput or air-gapped verifiers, pre-fetch the well-known feeds and pass them in:

```ts
import { verifyReceipt, fetchKeyBundle, fetchRevocations } from '@tunnelmindai/receipt-verify';

const [keys, revocations] = await Promise.all([fetchKeyBundle(), fetchRevocations()]);

const result = await verifyReceipt(receipt, { keys, revocations });
```

For fully-offline verification (pure crypto + embedded public_key only):

```ts
const result = await verifyReceipt(receipt, {
  noFetchKeys: true,
  noFetchRevocations: true,
});
```

## Rotation-overlap mode

When the issuer rotates a key, both the old and new key are live for ~24h. During that window, accept a key-bundle mismatch as a warning:

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
| `keys` | (fetched) | Pre-fetched `KeyBundle` to skip the network |
| `noFetchKeys` | `false` | Skip key-bundle resolution entirely |
| `keysUrl` | `tunnelmind.ai/.well-known/receipt-signing-key.json` | Self-hosted issuer override |
| `revocations` | (fetched) | Pre-fetched `RevocationFeed` |
| `noFetchRevocations` | `false` | Skip revocation check entirely |
| `revocationsUrl` | `tunnelmind.ai/.well-known/receipt-revocations.json` | Self-hosted issuer override |
| `allowKeyMismatch` | `false` | Demote key-mismatch error → warning |
| `fetcher` | `globalThis.fetch` | Custom fetch (e.g., for tests) |

### Lower-level exports

`fetchKeyBundle`, `resolveKey`, `clearKeyCache`, `fetchRevocations`, `isKeyRevoked`, `isReceiptRevoked`, `clearRevocationCache`, `canonicalize`, `canonicalizeBytes`, `RECEIPT_VERSION`.

## Verifying receipts you didn't issue

Receipts are designed to be verifiable by anyone — the public key is embedded in the receipt and validated against TunnelMind's published key bundle. You don't need credentials, an account, or any prior relationship with the issuer.

That said: the key bundle and revocation feed must be retrievable from a source you trust. The defaults point to `tunnelmind.ai`; for receipts issued by another producer, point `keysUrl` / `revocationsUrl` at the producer's well-known endpoints.

## Spec drift

The JCS canonicalizer in `src/jcs.ts` is **bit-identical** to the issuer-side serializers in `scry-server/src/lib/receipt_v1.js` and `tunnelmind-data-api/api/utils/receipt-v1.js`. Any change to one MUST be mirrored across all three. The frozen wire vector lives in this package's `test/golden.test.js` to catch silent drift.

## License

Apache-2.0. The receipt-format spec text itself is CC-BY-4.0 (separately hosted).

## Related

- [`@tunnelmindai/atap`](https://www.npmjs.com/package/@tunnelmindai/atap) — ATAP receipt verifier (different format, complementary use case)
- [`@tunnelmindai/eat`](https://github.com/TunnelMind/atap/tree/main/packages/eat-js) — EAT Profile v0.1 verifier (RFC 9711 alternative serialization of the same claim set)
- [`agent-onboarding.md`](https://tunnelmind.ai/agent-onboarding.md) — the 5-call golden path that uses these receipts end-to-end
