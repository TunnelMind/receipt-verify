# Changelog

## Unreleased

### Added

- Transparency-log verification in the library, on WebCrypto (Workers, Deno, Bun, Node): `verifyReceipt()` takes `inclusion: { proof, sth?, logKeys }` and reports `result.log.status` (`included` | `failed` | `not_checked`); `requireInclusion` makes a missing proof an error. New exports `verifySth`, `verifyReceiptInclusion`, `verifySthConsistency`, `receiptLeafHash`, `LogMonitor`, `MemorySthStore`, and the RFC 9162 primitives `leafHash`, `nodeHash`, `verifyInclusion`, `verifyConsistency`, `parseHash` (src/merkle.ts, src/log.ts). Previously inclusion and consistency existed only in `scripts/`, which is not published (2026-11-07).
- `LogMonitor` persists the last accepted STH per log and only accepts an advance proven append-only; reports `rollback`, `fork` (two signed roots for one size), `unproven` and `invalid`, and never stores an STH that failed (2026-11-07).
- Log keys are pinned separately from receipt keys (`logKeys`); the receipt-signing bundle is never used to verify an STH. Optional `signature.key_id` and `log_id` on STHs are bound when present; `requireKeyId` refuses an STH without a key_id (2026-11-07).
- Consistency tests: exhaustive inclusion and consistency for every tree up to 33 leaves against a recursive RFC 6962 reference, plus tamper, fork and rollback cases; the src/ and scripts/ verifiers are cross-checked (test/log.test.mjs) (2026-11-07).

### Security

- `scripts/verify-log.mjs consistency` took both roots from the proof document and never checked an STH signature, so any self-consistent proof passed, including one for a forked history. It now requires `<proof.json> <older_sth.json> <newer_sth.json> --key <b64>`, takes the roots from the two pinned-key STHs, and exits 1 if the proof's own roots or sizes disagree with them. The old one-argument form exits 2 (2026-11-07).

- `attestation_strength` must be one of `self-asserted`, `software`, `tee-tpm`, `silicon-root`: a receipt without the field or with any other value (an unknown tier ranked below every ceiling; a prototype name such as `constructor` ranked as a function) now fails with `attestation_strength: unrecognized value ...`, under `unsafeSkipStrengthCeiling` too (2026-10-21).
- `signature.value` must be the canonical padded standard base64 of the signature: a copy with whitespace, a missing `=` pad or stray low bits in the last character decoded to the same bytes and verified while hashing to a different `chain.previous_receipt_hash` link; it now fails with `signature verification failed: signature.value is not canonical standard base64` (2026-10-22).

## 2.0.0 - 2026-10-17

### Breaking

- The signature is verified against the bundle key looked up by `signature.key_id` (`keys` > `keysUrl` > the shipped `PINNED_KEY_BUNDLE`), never the embedded `public_key`; a non-empty `key_id` is required (V001).
- A failed key-bundle fetch is an error, not a warning (V002).
- `noFetchRevocations` is replaced by `unsafeSkipRevocations`; a failed revocation-feed fetch is an error (V005).
- The CLIs trust pinned keys only: `verify-log.mjs inclusion` requires `--key`, `--receipt` and an STH; `verify-verdict.mjs` checks the checkpoint and witnesses only against `--log-key` / `--witness-keys` (V004).
- JCS rejects lone surrogates instead of mapping them to U+FFFD (V006).

### Security

- Every resolved key must be active/rotated and inside `[created_at, rotation_after]` at the receipt's timestamp (V003).
- `allowKeyMismatch` only accepts another usable entry of the same bundle, matched by `public_key`, and the revocation check covers the key that actually verified (V003).
- A key revoked for `compromise` rejects receipts whatever their timestamp (V005).

### Fixed

- New `previous` option makes the chain check hard: `previous_receipt_hash` and `sequence` + 1 must match (V006).
- The revocation cache is keyed by URL with a TTL (V005).
