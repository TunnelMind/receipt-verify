# Changelog

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
