# @tunnelmindai/receipt-verify

> **Part of TunnelMind — a research house. Facts, not verdicts.**
> Four lenses on one signed corpus: **Scry** (*who is attacking?*) · **Sigil** (*who can you trust?*) · **Tracker** (*who is watching?*) · **GhostRoute** (*where does traffic actually go?*). Exhibits return as Ed25519-signed receipts (RFC 8785 JCS) that verify offline without trusting TunnelMind; the same receipt is the foundation of the accountability kit for agents that spend money (public demo: [tunnelmind.ai/weather](https://tunnelmind.ai/weather)).
> This package serves: **the receipt verifier** — the offline check under the kit: a Receipt v1 from the Data API, tm-crawl or the weather agent verifies here with a pinned key bundle and no call to TunnelMind. Apache-2.0. See [tunnelmind.ai/standards/receipt-format/v1](https://tunnelmind.ai/standards/receipt-format/v1).

Reference TypeScript verifier for the [TunnelMind Receipt Format v1.0](https://tunnelmind.ai/standards/receipt-format/v1). Implements §4 (Verification procedure) end-to-end plus §8 (Revocation) lookups.

## Install

```bash
npm install @tunnelmindai/receipt-verify
```

Zero runtime dependencies. Targets WebCrypto SubtleCrypto + `fetch` — runs on Node ≥20, Cloudflare Workers, Deno, Bun.

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
5. **Attestation strength** — `receipt.attestation_strength` must be one of `self-asserted`, `software`, `tee-tpm`, `silicon-root` (missing or anything else is an error); reject if it exceeds the bundle key's declared strength
6. **Revocation** — use `opts.revocations`, else fetch `https://tunnelmind.ai/.well-known/receipt-revocations.json` (a failed fetch is an error):
   - if `signature.key_id` (or the key that actually verified, see `allowKeyMismatch`) is revoked for `compromise`, reject whatever the receipt's timestamp
   - if it is revoked for another reason AND the receipt was signed after `revoked_at`, reject (signed before: warning)
   - if `receipt_id` is in `revoked_receipts`, reject
7. **Chain sanity** — warn (not reject) if `chain.sequence` and `previous_receipt_hash` are inconsistent. Pass `previous` (the prior receipt) to make it a hard check: `previous_receipt_hash` must equal the SHA-256 of the previous receipt's `signature.value` (UTF-8 bytes), `0x`-prefixed and `sequence` must be its sequence + 1

Checks 1-5 need no network by default: the key bundle is the pinned one unless you pass `keysUrl`. Check 6 fetches the revocation feed unless you pass `revocations`; it can only be turned off with `unsafeSkipRevocations`.

## Offline + pinned modes

### Key pinning

Trust comes only from pinned keys, never from a key the receipt (or log
checkpoint, or cosignature) carries. The pinned keys are:

- the bundle shipped with the package (`PINNED_KEY_BUNDLE` in `dist/pinned-keys.js`), used by default;
- a bundle you pass as `opts.keys` (or fetch from a `keysUrl` you choose);
- for the CLIs: `--keys` (`verify-verdict.mjs`, defaults to the shipped bundle), `--key` (`verify-log.mjs inclusion`), `--witness-keys` and `--log-key` (`verify-verdict.mjs`, both default to the active/rotated entries of `--keys`, matched by `key_id`).

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

### `verifyReceiptJson(text, opts?)`

`verifyReceipt` over raw receipt text. It refuses an object that repeats a member name at any depth (`duplicate key "<name>"`; `JSON.parse` would silently keep the last one), reports other parse errors as `receipt JSON: <message>`, and never throws; otherwise the result equals `verifyReceipt(JSON.parse(text), opts)`. Prefer it when you hold the receipt as text.

### `VerifyOptions`

| Option | Default | Purpose |
|---|---|---|
| `keys` | `PINNED_KEY_BUNDLE` | Key bundle to resolve `key_id` against; takes precedence over `keysUrl` |
| `noFetchKeys` | `false` | Never fetch `keysUrl`; fall back to the pinned bundle (or `keys`) |
| `keysUrl` | (none: pinned bundle) | Fetch the key bundle from this URL (e.g., self-hosted issuer); a failed fetch is an error |
| `revocations` | (fetched) | Pre-fetched `RevocationFeed`; offline callers pass this |
| `unsafeSkipRevocations` | `false` | **UNSAFE**: disable revocation checking, so revoked or compromised keys verify |
| `revocationsUrl` | `tunnelmind.ai/.well-known/receipt-revocations.json` | Self-hosted issuer override; a failed fetch is an error |
| `unsafeSkipStrengthCeiling` | `false` | **UNSAFE**: disable the attestation-strength ceiling (step 5); the four-tier validation still runs |
| `allowKeyMismatch` | `false` | Accept (with a warning) an embedded `public_key` that is another usable entry in the same bundle; see Rotation-overlap mode |
| `previous` | (none) | The prior receipt; makes the chain check hard (hash link + `sequence` + 1) |
| `fetcher` | `globalThis.fetch` | Custom fetch (e.g., for tests) |
| `inclusion` | (none) | `{ proof, sth?, logKeys, requireKeyId?, logId? }`: prove the receipt is in the transparency log under pinned **log** keys (`logKeys`: the log's key document, e.g. `PINNED_LOG_KEYS`, or a key array); a failed proof is an error. See below |
| `requireInclusion` | `false` | Make a missing inclusion proof an error. `result.log.status` reports `not_checked` either way |

### Lower-level exports

`fetchKeyBundle`, `resolveKey`, `keyUsableAt`, `clearKeyCache`, `DEFAULT_KEYS_URL`, `KEY_BUNDLE_CACHE_TTL_MS`, `PINNED_KEY_BUNDLE`, `PINNED_KEYS_FETCHED_AT`, `PINNED_LOG_KEYS`, `PINNED_LOG_KEYS_FETCHED_AT`, `LOG_KEYS_URL`, `checkLogKeyDoc`, `fetchRevocations`, `isKeyRevoked`, `isReceiptRevoked`, `clearRevocationCache`, `DEFAULT_REVOCATIONS_URL`, `REVOCATION_CACHE_TTL_MS`, `canonicalize`, `canonicalizeBytes`, `parseJsonStrict`, `bytesToHex`, `sha256HexPrefixed`, `RECEIPT_VERSION`, and the types `Receipt`, `VerifyOptions`, `VerifyResult`, `KeyBundle`, `SigningKeyEntry`, `AttestationStrength`, `RevocationFeed`, `JsonValue`, `LogKeyDoc`, `LogKeyDocEntry`, `LogKeyHandover`. See `ARCHITECTURE.md` for the module map and trust boundaries.

## Transparency-log inclusion and consistency (in the library)

A signature proves who issued a receipt. It does not prove the receipt is in
the log, or that the log was never rewritten. Both now run wherever
`verifyReceipt()` runs (WebCrypto, no Node builtins):

```ts
import { verifyReceipt, LogMonitor, PINNED_LOG_KEYS } from '@tunnelmindai/receipt-verify';

// The log's key document as shipped with this package (see "Log keys" below).
const logKeys = PINNED_LOG_KEYS;
const logId = 'tunnelmind-receipts-log-v1';
const proof = (await (await fetch(`https://data.tunnelmind.ai/v1/receipts/log/proof?receipt_id=${id}`)).json()).data;

const r = await verifyReceipt(receipt, { inclusion: { proof, logKeys, logId, requireKeyId: true }, requireInclusion: true });
r.log; // { status: 'included', tree_size, leaf_index, log_key_id, log_key: 'shared_with_receipts' }
```

- `result.log.status` is `included` (proven), `failed` (a proof was given and
  did not verify: also an error), or `not_checked` (no proof given).
- The leaf is recomputed from the receipt bytes: `SHA-256(0x00 || JCS(receipt))`.
  The proof's `leaf_hash` and roots are never trusted; the root and tree size
  come only from a signed tree head (the `sth` argument, else `proof.sth`).
- RFC 9162 proof math does not bind the tree size by itself (a size-3 proof
  also checks out "for size 4"), so every size is taken from the STH and a
  proof with different sizes is refused.

### Log keys: the key document, today and after the cut-over

`logKeys` is either the log's **key document** (`LogKeyDoc`) or an array of
pinned keys (`LogKeyEntry[]`, see "Array mode" below). `verifyReceipt`
inclusion, `verifySth`, `verifyReceiptInclusion`, `verifySthConsistency` and
`LogMonitor` take both.

A key document lists the log's signing keys by tree size: each entry signs
heads of sizes `from_tree_size` to `until_tree_size` (`null` = open-ended).
Every entry after the first carries a hand-over, a statement signed by the
previous entry's key that the log moves to the new key at that size under
that root. The first entry must be a receipt-signing key. `checkLogKeyDoc(doc,
receiptKeys?)` runs these rules and returns `null` or a short reason string.

- **Today (shared).** The live log (`log_id` `tunnelmind-receipts-log-v1`)
  signs tree heads with the receipt-signing key `tm-receipt-2026-05`.
  `PINNED_LOG_KEYS` is a one-entry document for that key, open-ended from
  size 0, and results report `log_key: 'shared_with_receipts'`. Inclusion
  then proves the receipt is in the issuer's own log, not that a second
  party witnessed it. `LOG_KEYS_URL` was not served yet on
  `PINNED_LOG_KEYS_FETCHED_AT`, so the pin was written from the format, not
  copied from the server.
- **After the cut-over.** The log gets a key of its own (`tm-log-YYYY-MM`) at
  some tree size m. The served document then has two entries: the receipt
  key for sizes [0, m], and the log key from m on, with a hand-over signed by
  the receipt key. A head signed by the log key at a size ≥ m is valid and
  reports `log_key: 'separate'`. A head signed by the receipt key above m is
  refused with `tree_size_out_of_range`. A head at exactly m, under either
  key, whose root is not the hand-over's root is refused with
  `root_mismatch`.
- **What document mode checks.** The head must name its key in
  `signature.key_id`, and only that entry is tried (`unknown_key_id` if the
  document has none). The head's `log_id` must be the document's. The
  tree-size range replaces the time window: no `created_at` /
  `rotation_after` check runs, and `requireKeyId` is moot (a key id is always
  required). A head under a handed-over key must also carry `key_id` in its
  signed body. A refusal is one fixed string, the same one
  `scripts/verify-log.mjs` prints, in `SthResult.reason` (and in `errors`).

The document is served at `LOG_KEYS_URL`. There is no fetch helper; use the
served document when there is one and the pin only when there is none:

```ts
import { LOG_KEYS_URL, PINNED_LOG_KEYS, checkLogKeyDoc } from '@tunnelmindai/receipt-verify';

const res = await fetch(LOG_KEYS_URL);
if (!res.ok && res.status !== 404) throw new Error(`log key document: HTTP ${res.status}`);
const logKeys = res.status === 404 ? PINNED_LOG_KEYS : await res.json();
const bad = await checkLogKeyDoc(logKeys);
if (bad) throw new Error(`log key document: ${bad}`);
```

Fall back to `PINNED_LOG_KEYS` **only on a 404**. A served document that
fails the check is an error, never a reason to fall back: an attacker who can
break the served file must not be able to push you onto an older pin.
The explicit `checkLogKeyDoc` call also refuses a served body that is not a
document at all (a bare array would otherwise be read as array mode, which
trusts whatever keys it lists). If you skip it, verification still fails
closed on a bad document, with `reason` `invalid_key_doc` or
`first_key_not_pinned`, and the `LogMonitor` constructor throws `TypeError`
for every rule it can check synchronously (a bad hand-over signature shows
as `invalid` on each `observe()` instead).

Limits, stated plainly:

- **A fetched document is only as strong as the receipt key.** Nothing in a
  document is trusted by itself: `keys[0].public_key` must equal, as decoded
  bytes, a pinned receipt key that is active or rotated (otherwise
  `first_key_not_pinned`), and the hand-over to the log key is signed by that
  receipt key. Whoever holds the receipt key can hand the log over to a key
  of their choice.
- **Which receipt keys anchor a document.** `receiptKeys` in `SthOptions`,
  default `PINNED_KEY_BUNDLE.keys`. `verifyReceipt` passes its receipt bundle
  in use plus the pinned one, so a receipt bundle you supply as `keys` (or
  fetch with `keysUrl`) also roots log key documents.
- **Old sizes stay with the receipt key (ADR-047 §8).** After the cut-over a
  head signed by the receipt key at a size ≤ m with a valid signature is
  still accepted, by design: those heads were legitimately signed by it.
  A document cannot tell an old head from a new one forged with the receipt
  key for an old size. `LogMonitor` is the defence: it refuses a smaller
  tree and any advance without a consistency proof.
- **A stale pin.** After the cut-over an unchanged `PINNED_LOG_KEYS` knows
  only the receipt key, open-ended. Log-key heads fail with
  `unknown_key_id`, and receipt-key heads above the hand-over size are still
  accepted, until the pin is refreshed in a new release or you pass the
  served document.

### Array mode

Passing an array of keys works unchanged:

```ts
const logKeys = [{ key_id: 'tm-receipt-2026-05', algorithm: 'Ed25519', public_key: '<pinned b64>', status: 'active' }];
```

- **The array is the trust.** `logKeys` is required; the
  receipt-signing bundle is never consulted for the log on its own. If the
  STH names `signature.key_id`, only that pinned key is tried; `requireKeyId`
  refuses an STH without one. A key with `log_id` only signs for that log.
  A log key's status and `created_at`/`rotation_after` window are checked
  against the STH's `timestamp`.
- **Today the log and the issuer share a key**, so the array to pin today
  is that one receipt key, `tm-receipt-2026-05`.
- **Log-key mode: shared or separate.** The mode comes from your `logKeys`,
  compared by public key with the receipt-signing keys (`receiptKeys` in
  `SthOptions`, default `PINNED_KEY_BUNDLE.keys`; `verifyReceipt` passes its
  bundle in use plus the pinned one). Every log key a receipt key: mode
  `shared_with_receipts`, as the live log needs today. Any log key that is not a
  receipt key: mode `separate`, and then a log key equal to a receipt key is
  refused at load (`log key <id> is also a receipt-signing key`, before any
  STH is read; `LogMonitor`'s constructor throws), so a tree head signed by
  the receipt-issuing key never verifies. Pin either only receipt keys or
  only dedicated log keys, never a mix. Results report the mode as
  `log_key` (`SthResult`, `InclusionResult`, and `result.log` when
  `inclusion` was given).

### Monitoring

`LogMonitor` remembers the last STH it accepted (pluggable `SthStore`:
memory by default; implement `get`/`put` over a file, KV or a database) and
only accepts an advance it can prove append-only. With a key document it
follows the log across the cut-over: each head is judged under the document,
so a consistency proof may run from a receipt-key head to a log-key head.


```ts
const mon = new LogMonitor({ logId, logKeys, store, fetchConsistency: (m, n) => getConsistency(m, n) });
const r = await mon.observe(sth); // status: first | unchanged | advanced | unproven | fork | rollback | invalid
```

A smaller tree (`rollback`) or a second signed root for the same size
(`fork`) is evidence of log misbehaviour: keep both STHs. Nothing that fails
replaces the monitor's last good view. `logId` is required: the store is
keyed by the log you watch, never by the `log_id` an STH claims. One monitor
runs its `observe()` calls one at a time; monitors sharing one store are not
coordinated.

Lower-level: `verifySth`, `verifyReceiptInclusion`, `verifySthConsistency`,
`checkLogKeyDoc`, `receiptLeafHash`, and the raw RFC 9162 primitives `leafHash`, `nodeHash`,
`verifyInclusion`, `verifyConsistency`, `parseHash`.

## Verifying receipts you didn't issue

Receipts are designed to be verifiable by anyone — the receipt names its signing key by `key_id`, and the verifier checks the signature against that key in a pinned bundle (the receipt's embedded public key is only compared, never trusted). You don't need credentials, an account, or any prior relationship with the issuer.

That said: the key bundle and revocation feed must come from a source you trust. The defaults are the bundle pinned in this package and the `tunnelmind.ai` revocation feed; for receipts issued by another producer, pass their bundle as `keys` (or point `keysUrl` / `revocationsUrl` at the producer's well-known endpoints).

## Verifying the transparency log (`scripts/verify-log.mjs`)

The offline verifier for the receipt transparency log (RFC 6962 / RFC 9162
algorithms; node builtins only, zero library code):

```
node scripts/verify-log.mjs inclusion   <proof.json> [sth.json] (--key <b64> | --log-keys <doc.json> --receipt-key=<b64>) --receipt <receipt.json>
node scripts/verify-log.mjs consistency <proof.json> <older_sth.json> <newer_sth.json> (--key <b64> | --log-keys <doc.json> --receipt-key=<b64>)
node scripts/verify-log.mjs sth         <sth.json> <public_key_b64> [--receipt-key=<b64> [--allow-shared]]
node scripts/verify-log.mjs sth         <sth.json> --log-keys <doc.json> --receipt-key=<b64>
node scripts/verify-log.mjs handover    <doc.json> --receipt-key=<b64>
```

`proof.json` / `sth.json` are exactly the `data` objects returned by
`GET data.tunnelmind.ai/v1/receipts/log/{sth,proof,consistency}`.
`inclusion` verifies the STH against the pinned `--key` (never the key the
STH carries) and recomputes the leaf from the `--receipt` bytes.
`consistency` takes both roots from the two STHs, each verified under the
pinned `--key`; the proof's own `first_root`/`second_root` are only compared
against them (a proof alone is self-consistent by construction).

The `--key` forms and plain `sth <sth.json> <public_key_b64>` are unchanged.
The key-document modes are for a log whose key is handed over:

- `handover <doc.json> --receipt-key=<b64>` checks a key document: its
  ranges and hand-overs, and that `keys[0]` is the given receipt key. It
  prints `{"valid":…,"reason":…}`.
- `sth <sth.json> --log-keys <doc.json> --receipt-key=<b64>` checks one head
  against the document: the key named by `signature.key_id` must be in the
  document, sign the head and cover its tree size.
- `inclusion` / `consistency` take `--log-keys <doc.json> --receipt-key=<b64>`
  in place of `--key`. Each head is checked as `sth --log-keys` checks it, so
  a consistency proof may run from a head under the receipt key to a head
  under the log key. Give exactly one of `--key` and `--log-keys`: both,
  neither, or `--log-keys` without `--receipt-key`, exits 2.
- `sth <sth.json> <public_key_b64> --receipt-key=<b64>` adds `log_key` to the
  output: `own` when the log key differs from the receipt key,
  `shared_with_receipts` when it is the same key. Shared exits 1 unless
  `--allow-shared` is given.

A document cannot vouch for itself, so every `--log-keys` mode and `handover`
needs `--receipt-key` (exit 2 without it). Write it in the `=` form,
`--receipt-key=<b64>`: a key that starts with `-` is refused otherwise. Keys
and signatures must be in the standard base64 alphabet (`A-Z a-z 0-9 + /`,
`=` padding); base64url is refused. The refusal strings are the same ones the library reports in `SthResult.reason`.

`docs/OPA-INTEGRATION.md` shows how a PDP consumes the signed bundle.

## Verifying a reconciliation verdict (`scripts/verify-verdict.mjs`)

The standalone offline verifier for Reconciliation Verdict v1.0 receipts —
re-derives the verdict from receipt bytes with no call to TunnelMind
(signature, payload hash, log inclusion, witness cosignatures, verdict
re-derivation):

```
node scripts/verify-verdict.mjs [--keys <bundle.json>] [--log-key <b64>] \
  [--witness-keys <file.json|b64,b64>] <receipt.json|->
curl -s https://data.tunnelmind.ai/v1/verdict/<key> \
  | node scripts/verify-verdict.mjs -
```

Only pinned keys are trusted: `--keys` defaults to the bundle shipped in
`dist/pinned-keys.js` (run `npm run build` first). The checkpoint root is
proven by the witness cosignature over the canonical checkpoint. When absent,
`--witness-keys` and `--log-key` default to the active/rotated entries of
`--keys` (the shipped bundle by default), matched by `key_id`; explicit flags
override. A cosigner or checkpoint signer outside them fails. The log key is
only used when the checkpoint carries its own `signature`.

Its pure dependency chain lives in `scripts/verdict-lib/` — those modules
are the spec (the service runs the same code).

## Spec drift

The JCS canonicalizer in `src/jcs.ts` produces the same bytes as the issuer-side serializers in `scry-server/src/lib/receipt_v1.js` and `tunnelmind-data-api/api/utils/jcs.js` for every well-formed input; any change to one MUST be mirrored across all three. The one deliberate difference: this package refuses a lone UTF-16 surrogate (the issuers emit U+FFFD), so a receipt carrying one fails closed rather than letting two strings sign to the same bytes. The JCS tests live in `test/verify.test.mjs` and `test/properties.test.mjs` (with the shared helpers in `test/_helpers.mjs`); the frozen cross-implementation wire vectors are `test/vectors/jcs.json`, run here against all three entry points — the two independent implementations in this repo, `src/jcs.ts` and `scripts/verify-log.mjs` `jcs()`, plus `scripts/verdict-lib/jcs.js`, which re-exports `src/jcs.ts` and is pinned to it by identity (`test/jcs-vectors.test.mjs`) — and are the file Fareseal and atap vendor verbatim (their copies carry this file's sha).

`test/vectors/receipt-v1/` holds the Receipt v1.0 vectors shared with the Rust verifier (rune-record): `cases.json` (the key bundle, revocation feed and case list) plus 10 raw receipt files, each with one defect and its expected verdict, generated by `scripts/gen-receipt-v1-vectors.mjs` from public test-only seeds and checked by `test/receipt-v1-vectors.test.mjs`.

## Migrating from 1.x to 2.0.0

2.0.0 closes trust gaps; each item below can turn a receipt that 1.x accepted
into a rejection. See `CHANGELOG.md`.

- **The key is looked up by `key_id` and pinned.** `signature.key_id` is required. The signature is verified against the bundle key (`keys` > `keysUrl` > the shipped `PINNED_KEY_BUNDLE`), which must be active/rotated and inside its validity window. The embedded `public_key` is no longer verified against; a mismatch is an error.
- **A failed key-bundle fetch is an error**, not a warning.
- **`allowKeyMismatch` is narrower**: it only accepts another usable entry of the same bundle, matched by `public_key`.
- **The 1.x option that skipped the revocation fetch is now `unsafeSkipRevocations`** (named for what it does). Offline callers should pass `revocations` instead.
- **A failed revocation-feed fetch is an error.** A key revoked for `compromise` rejects regardless of the receipt's timestamp.
- **The CLIs trust pinned keys only.** `verify-log.mjs inclusion` requires `--key` (or, since 3.0.0, `--log-keys` with `--receipt-key`), `--receipt` and an STH; `verify-verdict.mjs` verifies the issuer against `--keys` (default: the shipped bundle) and the witness cosignature (the checkpoint proof) and any checkpoint signature against `--witness-keys` / `--log-key`, which default to the active/rotated `--keys` entries matched by `key_id`.
- **JCS rejects lone surrogates** (1.x silently mapped them to U+FFFD); such a payload fails canonicalization.
- **New: `previous` makes a hard chain check** (opt-in): with it, `previous_receipt_hash` and `sequence` mismatches are errors; without it the chain checks stay warnings.

## License

Apache-2.0. The receipt-format spec text itself is CC-BY-4.0 (separately hosted).

## Related

- [`rune-record`](https://github.com/TunnelMind/rune-record) — the Rust signer/verifier for the same Receipt v1 format (RFC 8785 JCS + Ed25519); it vendors this package's `test/vectors/jcs.json` so both agree byte for byte
- [`@tunnelmindai/atap`](https://www.npmjs.com/package/@tunnelmindai/atap) — ATAP receipt verifier (different format, complementary use case)
- [`@tunnelmindai/eat`](https://github.com/TunnelMind/atap/tree/main/packages/eat-js) — EAT Profile v0.1 verifier (RFC 9711 alternative serialization of the same claim set)
- [`agent-onboarding.md`](https://tunnelmind.ai/agent-onboarding.md) — the 5-call golden path that uses these receipts end-to-end
