# Changelog

## 4.0.0 — unreleased (not published)

### Breaking

Major bump 3.0.0 -> 4.0.0: log inclusion is on by default.

- `verifyReceipt()` and `verifyReceiptJson()` now require transparency-log inclusion: `requireInclusion` defaults to `true`. With no `inclusion` given and the pinned key bundle in use, the proof is fetched from `DEFAULT_LOG_PROOF_URL` (`https://data.tunnelmind.ai/v1/receipts/log/proof?receipt_id=…`, override with `logProofUrl`, fetched with `fetcher`) and checked under `PINNED_LOG_KEYS`; the fetched proof, head and leaf hash are trusted no more than a supplied proof. A receipt that is not proven is invalid: `log.status` is `pending` when the log holds it but no signed head covers it yet (the log signs a new head about hourly), `absent` when the log has no record of it, and `not_checked` with `log inclusion: proof fetch failed: …` when the proof cannot be fetched. The receipt_id is sent only after every other check has passed, over https, with a 10 s timeout, a 64 KiB cap on the response and no redirects (a 3xx could carry the id to another host). With `keys` or `keysUrl` (another issuer) nothing is fetched and no `inclusion` is an error `log inclusion: required but no inclusion proof was supplied …`, so another issuer's receipt id never reaches TunnelMind's log. Before, a receipt that was never logged verified with `log.status` `not_checked`. Migration: pass `inclusion` when you hold the proof (offline), or `requireInclusion: false` to keep the 3.x behaviour (signature checked, log membership not). Old receipts: every receipt that went into data-api's ledger is in the log, so its proof is served; a receipt issued before the ledger, or one returned with `receipt_logged: false`, has no proof and now fails unless you opt out (2026-11-20).
- `LogStatus` gains `pending` (the log holds the receipt, not in a signed tree head yet) and `absent` (the log has no record of it), told apart by the proof endpoint's own error text, matched whole (a 404 for "not yet sequenced" or "no receipt", a 400 for a leaf past the latest head). Neither is valid: pending is the log's word, and a key holder could leave a receipt pending forever. Migration: treat `pending` as "verify again after the next head"; code that switched on the three old statuses must handle the two new ones (2026-11-20).
- The default call now makes a network request per receipt: the receipt_id goes to `data.tunnelmind.ai`. Fully offline verification needs `revocations` and `inclusion` (or the opt-out). Receipts from another issuer, tm-crawl's included (its own key, its own store log), never reach TunnelMind's log and need `inclusion` or `requireInclusion: false`; weather-agent receipts are not in this log yet (2026-11-22).
- `PINNED_KEY_BUNDLE` and `PINNED_LOG_KEYS` are frozen, all the way down: code that edited them (to add a key) now throws a TypeError. Pass `keys` or `inclusion.logKeys` instead (2026-11-22).
- `scripts/verdict-lib` passes `requireInclusion: false` to its envelope check: a verdict receipt's own inclusion check is the checkpoint proof, unchanged (2026-11-20).

### Added

- `logKeys` on `verifyReceipt`: the log's key document for the default fetch path, in place of `PINNED_LOG_KEYS`, so heads signed after a log-key change verify on an installed 4.0.0 without a new release. It is trusted only as far as it chains back to the pins (first key a pinned receipt key, each later key handed over by the one before, `log_id` the pinned log's), and it must be a key document: a bare key array is refused before anything is fetched, because array mode has no anchor (2026-11-22, array refusal 2026-11-28).
- `result.log.sth_timestamp`: the proving head's own signed date. It is the issuer's claim (the log key is the receipt key today), so it does not prove a receipt was logged before a deadline; a draft `includedBy` option that implied it would was dropped before release (2026-11-22).
- `fetchInclusionProof(receiptId, { url?, fetcher?, timeoutMs? })`, `LogProofUnavailable` (its `kind`: `pending`, `absent`, `unavailable`), `DEFAULT_LOG_PROOF_URL`, `DEFAULT_LOG_PROOF_TIMEOUT_MS`, `MAX_LOG_PROOF_BYTES` and the `FetchProofOptions` type. Only ids matching the endpoint's `[A-Za-z0-9-]{1,64}` are sent, only to an https URL with no user name or password; it throws nothing but `LogProofUnavailable` (2026-11-20, hardened 2026-11-22).

### Fixed

- `verifyReceipt` never throws: a receipt nested too deep to walk, or a hostile option value, is returned as an error with `valid: false` (it threw a RangeError or TypeError before) (2026-11-22).
- Tests: review hardening (test/hardening.test.mjs: frozen pins, never throws, bad endpoint, timeout, size cap), a log-key change through `logKeys` (and three documents that do not chain to the pins, a bare key array, a document for another log), redirects refused, error texts only whole and on their own status, only `false` opts out, a 400 past the head, whole-text matching, no fetch for an already-invalid receipt; pending, absent; the default fetch path end to end, a forged head, a lying leaf hash, wrong index and another log's head from the fetched proof, every way a fetch can fail, the opt-out, the URL override and a refused receipt id (test/inclusion-default.test.mjs) (2026-11-20).

## 3.0.0 — 2026-11-17 (published to npm)

### Breaking

Major bump 2.0.0 -> 3.0.0; `verifyReceipt` is stricter, see each item's migration.

- `verifyReceipt()` now errors with `signature.public_key: required string` when `signature.public_key` is absent or not a string, and `receipt_id: required string` when `receipt_id` is absent or not a string; before, a correctly signed receipt without either still verified. Migration: receipts from rune-record and Fareseal always carry both; add them to hand-built receipts and re-sign (2026-11-10).
- A key bundle entry with no (or null) `attestation_strength` is now ranked `self-asserted` in the ceiling check, so a receipt claiming a higher tier fails with `attestation_strength ceiling violated: receipt=<x> > key=(none, treated as self-asserted)`; before, such a key skipped the ceiling and any tier up to `silicon-root` passed. Migration: add `attestation_strength` to each key entry in your bundle (or pass `unsafeSkipStrengthCeiling`) (2026-11-10).
- `verifyReceipt()` now errors with `number <n> is not a JS-safe integer` for every number anywhere in the receipt that fails `Number.isSafeInteger` (a float such as `1.5`, or an integer beyond ±(2^53-1)), as rune-record's `check_numbers` does; `-0` and `2^53-1` pass. Before, a correctly signed receipt carrying such numbers verified. Migration: encode floats and big integers as strings, or pass `unsafeAllowNonIntegers` (scripts/verdict-lib does, for its float weights) (2026-11-10).
- A mixed log-key set is now refused: when at least one pinned `logKeys` entry is not a receipt-signing key (separate mode), any entry whose public key equals a receipt key fails `verifySth`, `verifyReceiptInclusion`, `verifySthConsistency` and `verifyReceipt` inclusion with `log key <id> is also a receipt-signing key`, and the `LogMonitor` constructor throws; before, such a set let an STH signed by the receipt-issuing key verify. Receipt keys come from the new `SthOptions.receiptKeys` (default `PINNED_KEY_BUNDLE.keys`; `verifyReceipt` uses its bundle plus the pinned one). Migration: pin either only receipt keys (shared, as the live log needs today) or only separate log keys (2026-11-10).

### Added

- Key-document mode for the log: `logKeys` may be the log's key document (`LogKeyDoc`: keys by tree-size range, each later key endorsed by a hand-over the previous key signed) instead of a key array, in `verifySth`, `verifyReceiptInclusion`, `verifySthConsistency`, `LogMonitor` and `verifyReceipt` inclusion. The first key must be an active or rotated receipt-signing key (`SthOptions.receiptKeys`, default `PINNED_KEY_BUNDLE.keys`; `verifyReceipt` uses its bundle plus the pinned one), the head must name its key, and that key's tree-size range replaces the time window, so verification follows the log across a cut-over from the receipt key to a key of its own. New `checkLogKeyDoc(doc, receiptKeys?)` returns `null` or the reason; `SthResult.reason` carries the refusal string (`tree_size_out_of_range`, `root_mismatch`, `unknown_key_id`, `invalid_key_doc`, `first_key_not_pinned`, …), the same one the CLI prints. The `LogMonitor` constructor throws `TypeError` on a document that fails the synchronous rules or is for another log. New types `LogKeyDoc`, `LogKeyDocEntry`, `LogKeyHandover`. Array mode is unchanged (2026-11-13).
- `scripts/verify-log.mjs` key-document modes: `handover <doc.json> --receipt-key=<b64>` (check a key document), `sth <sth.json> --log-keys <doc.json> --receipt-key=<b64>` (check a head against it), `sth <sth.json> <public_key_b64> --receipt-key=<b64> [--allow-shared]` (reports `log_key` `own` or `shared_with_receipts`; shared exits 1 unless allowed), and `--log-keys <doc.json> --receipt-key=<b64>` in place of `--key` on `inclusion` and `consistency` (exit 2 when both or neither is given). The `--key` forms and plain `sth` are unchanged (2026-11-13).
- `PINNED_LOG_KEYS` (the log's key document as shipped: today one entry, the receipt key `tm-receipt-2026-05`, open-ended), `PINNED_LOG_KEYS_FETCHED_AT` and `LOG_KEYS_URL` (where the document is served). The README shows the pattern: use the served document, fall back to the pin only on a 404, and treat a served document that fails the check as an error (2026-11-13).
- `test/vectors/receipt-v1/`: Receipt v1.0 vectors shared with the Rust verifier (rune-record): `cases.json` (key bundle, revocation feed, case list) and 10 raw receipts (`valid` plus nine single-defect cases: `unknown_key`, `expired_key`, `revoked_key`, `tier_too_high`, `missing_public_key`, `missing_receipt_id`, `float_payload`, `duplicate_key`, `bad_timestamp`), generated byte-stable by `scripts/gen-receipt-v1-vectors.mjs` from public test-only seeds and checked by `test/receipt-v1-vectors.test.mjs` (2026-11-10).
- `verifyReceiptJson(text, opts)`: verifies raw receipt text and refuses a repeated member name at any depth with `duplicate key "<name>"` (names compared decoded), where `JSON.parse` silently keeps the last one; other parse errors give `receipt JSON: <message>`, it never throws, and otherwise it returns `verifyReceipt(parsed, opts)`. The strict parser is exported as `parseJsonStrict` (2026-11-10).
- `log_key: "shared_with_receipts" | "separate"` on `SthResult`, `InclusionResult` and `VerifyResult.log` (when `inclusion` was given), and the `LogKeyMode` type: whether the pinned log keys are the receipt-signing keys or a key of their own (2026-11-10).
- Transparency-log verification in the library, on WebCrypto (Workers, Deno, Bun, Node): `verifyReceipt()` takes `inclusion: { proof, sth?, logKeys }` and reports `result.log.status` (`included` | `failed` | `not_checked`); `requireInclusion` makes a missing proof an error. New exports `verifySth`, `verifyReceiptInclusion`, `verifySthConsistency`, `receiptLeafHash`, `LogMonitor`, `MemorySthStore`, and the RFC 9162 primitives `leafHash`, `nodeHash`, `verifyInclusion`, `verifyConsistency`, `parseHash` (src/merkle.ts, src/log.ts). Previously inclusion and consistency existed only in `scripts/`, which is not published (2026-11-07).
- `LogMonitor` persists the last accepted STH per log and only accepts an advance proven append-only; reports `rollback`, `fork` (two signed roots for one size), `unproven` and `invalid`, and never stores an STH that failed (2026-11-07).
- Log keys are pinned on their own (`logKeys`); the receipt-signing bundle is never consulted for an STH on its own. The live log signs STHs with the receipt key `tm-receipt-2026-05`, so today that key is pinned as the log key. Optional `signature.key_id` and `log_id` on STHs are bound when present; `requireKeyId` refuses an STH without a key_id. A log key's status and `created_at`/`rotation_after` window are checked against the STH `timestamp` (2026-11-07).
- `LogMonitor` requires `logId` and keys its store by it, never by the STH's own `log_id`; `observe()` calls on one monitor are serialized (2026-11-07).
- `keyUsableAt()` takes an optional `subject` for its reasons, and a key with a window now fails a non-finite timestamp instead of passing it (2026-11-07).
- Consistency tests: exhaustive inclusion and consistency for every tree up to 33 leaves against a recursive RFC 6962 reference, plus tamper, fork and rollback cases; the src/ and scripts/ verifiers are cross-checked (test/log.test.mjs) (2026-11-07).

### Changed

- Renamed to Fareseal in 4 prose mentions (ARCHITECTURE.md, README.md, test/jcs-vectors.test.mjs, the `about` string of test/vectors/jcs.json); no identifier or signed value changed. test/vectors/jcs.json's sha256 is now `b294a60b53b743eedb6f77c2473abe9e1b1f1d2eec631ad8a36018a82cad3a2d`: Fareseal and atap re-sync their vendored copies (2026-11-10).
- `scripts/verdict-lib/jcs.js` now re-exports `canonicalize`/`canonicalizeBytes` from `dist/index.js` instead of carrying a vendored copy (internal: `scripts/` is unpublished; behavior identical on test/vectors/jcs.json) (2026-11-10).

### Fixed

- Base64 strictness in the key-document checks: every key and signature field must be in the standard base64 alphabet with `=` padding only (`isB64` in `scripts/verify-log.mjs`; the library applies the same pattern to keys and takes only canonical padded signatures), so a base64url spelling or one with other characters is refused (`bad_entry` for a document key). The Data API's copy of the verifier decodes with `Buffer.from(s, 'base64')`, which also accepts base64url and skips junk characters; a document it accepts in such a spelling is refused here (2026-11-13).
- `engines` said Node >=18, but Node 18 has no `globalThis.crypto`, so importing the package threw there on every version. The floor is now Node >=20 (Node 18 reached end of life 2025-04-30); a CI test job runs Node 20/22/24 on every PR (2026-11-07).

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
