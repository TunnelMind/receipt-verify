# rv-strict-1 — the JS verifier stops passing what the Rust one rejects, and has one canonicalizer

**Repo:** `TunnelMind/receipt-verify` (public, `@tunnelmindai/receipt-verify` 2.0.0 on npm)
**Source:** 2026-11-10 code review, `~/.crew/coord/review-2026-11-10/01-receipt-core.md` §3 (RV-1, RV-2, RV-6), §6 (JCS count), §7 (Rust/JS disagreement table)
**Base checked:** `origin/main` = `f69fc1d`. Every finding cited below was re-read at that commit and is still present (see "Finding check").

## Intent

We make `verifyReceipt` reject every receipt the Rust `receipt_v1::verify` rejects for a reason the JS side currently ignores (no `public_key`, no `receipt_id`, a float, a duplicate key), close the tier-ceiling skip, separate the log key from the receipt keys, and keep one JCS canonicalizer. It ships as a new major version with shared cross-implementation vectors that the Rust crate reads unchanged. We do **not** publish it.

Key sentences from the prompt:

> "`verifyReceipt` fails a receipt with no `public_key` or no `receipt_id` (today it passes)."
> "The tier ceiling is never skipped: a bundle key without `attestation_strength` is treated as the lowest tier."
> "One JCS canonicalizer in the package (the review counted three). The others become imports of it; byte-for-byte output proven by a test over the existing fixtures."
> "when a log key is pinned, a tree head signed by the receipt-issuing key is rejected; a log key equal to any pinned receipt key is rejected at bundle load. Until a log key is pinned, behaviour is as today and the result object says `log_key: "shared_with_receipts"`."
> "Write them so the Rust crate can use the same JSON files unchanged."
> "This is a behaviour-tightening change: bump the major version in package.json and CHANGELOG; do NOT publish."
> "Existing behaviour not named here stays byte-identical."

## Finding check (against origin/main f69fc1d)

| Item | Review cite | Still present? |
|---|---|---|
| R001 / RV-6 | `src/index.ts:275` compares `public_key` only when present; `receipt_id` never checked (only used at `:221`, `:375`) | yes |
| R002 / RV-2 | `src/index.ts:336` `else if (signingKey?.attestation_strength && …)` skips the ceiling when the field is missing | yes |
| R003 | three JCS: `src/jcs.ts:46`, `scripts/verdict-lib/jcs.js` (vendored copy), `scripts/verify-log.mjs:53` `jcs()` | yes |
| R004 / RV-1 | `src/log.ts:21-24` header: the live log signs STHs with receipt key `tm-receipt-2026-05`; nothing stops a caller pinning a receipt key as a log key | yes |
| R005 | no receipt-level vectors exist; only `test/vectors/jcs.json` | yes |
| R007 | "tollbooth" appears exactly 4 times: `ARCHITECTURE.md:22`, `README.md:252`, `test/jcs-vectors.test.mjs:3`, `test/vectors/jcs.json:3` (all prose; no identifier, no signed value) | yes |

Note on R003: the published tarball (`package.json` `files`: `dist`, `src`, …) already holds exactly one canonicalizer; the other two live in `scripts/`, which is not published. The review itself says `verify-log.mjs`'s copy is "independent on purpose" (its header: "imports ONLY node: builtins"). See Q2.

## Open Questions

Each has a recommended default; the tasks are written against the defaults. "defaults" answers all.

- **Q1 (R004) — what turns on "a log key is pinned"?** The prompt's two rules collide if read literally (today every caller pins `tm-receipt-2026-05` as the log key, so "reject a log key equal to a receipt key" would break today's behaviour, which must stay). **Default:** the mode is decided by the caller's `logKeys` themselves.
  - *Shared mode* (today): every usable `logKeys` entry has a `public_key` that is also a receipt key (the receipt bundle in use, plus `PINNED_KEY_BUNDLE`). Behaviour is unchanged; results carry `log_key: "shared_with_receipts"`.
  - *Separate mode*: at least one `logKeys` entry is not a receipt key. Then any `logKeys` entry whose `public_key` equals a receipt key is refused when the keys are loaded (`verifyReceipt` with `inclusion`, `verifyReceiptInclusion`, `verifySth`, `verifySthConsistency`: an error; `LogMonitor` constructor: throws, as it already does for misuse). That also guarantees an STH signed by a receipt-issuing key never verifies. Results carry `log_key: "separate"`.
  - `verifySth` and friends learn the receipt keys from a new optional `SthOptions.receiptKeys` (default `PINNED_KEY_BUNDLE.keys`); `verifyReceipt` passes its bundle plus the pinned one.
- **Q2 (R003) — does `scripts/verify-log.mjs` also import the one canonicalizer?** **Default (recommended):** no. `scripts/verdict-lib/jcs.js` becomes a re-export of `dist/index.js` (as `verdict-lib/hash.js` already does); `verify-log.mjs` keeps its own `jcs()` because it is the deliberately independent second implementation that cross-checks the library. Answer "all three" to make it import too (its header and the cross-check note in `test/log.test.mjs` then change).
- **Q3 (R005 "float payload (reject)") — reject floats where, and for whom?** Today JS accepts any finite number. Verdict receipts carry float weights (`scripts/verdict-lib/tier.js:38-41`, 0.65 etc.), and the JS issuers (data-api, scry-server) sign whatever JSON they are given, so live receipts carrying floats would stop verifying. **Default:** `verifyReceipt` rejects any number anywhere in the receipt that is not a JS-safe integer (same rule as Rust `check_numbers`, `rune-record/src/receipt_v1.rs:67-80`); a new `unsafeAllowNonIntegers` option opts out, and `scripts/verdict-lib/verify-receipt.js:79` passes it (it already passes `unsafeSkipStrengthCeiling`). Josh confirms no live non-verdict receipt carries a float, or says otherwise.
- **Q4 (R005 "duplicate key (reject)") — a duplicate key is invisible once `JSON.parse` has run.** **Default:** add one exported entry point `verifyReceiptJson(text, opts)` that parses with a strict parser (refuses duplicate member names, otherwise identical to `JSON.parse`) and then calls `verifyReceipt`. `verifyReceipt(object)` is unchanged for this rule. The vectors are raw JSON files so both languages read the same bytes.
- **Q5 (R005 "the verdict name each must produce") — does the library emit the name?** **Default:** no new result field. The shared manifest names the expected verdict per case; each implementation's test maps its own errors to those names. Answer "add a field" to get `result.verdict` instead.
- **Q6 (R007) — `test/vectors/jcs.json` is vendored verbatim, by sha, into Fareseal and atap.** Changing its `about` text changes the sha. **Default:** rename it here (the file says "change it here first") and record the new sha in CHANGELOG so the vendoring repos re-sync; no vector changes.

## User Scenarios

### US1 — A receipt the Rust verifier rejects never passes JS (R001, R005 float/duplicate)
A third party verifies a receipt with this package and with `rune-record`.
- **Given** a receipt correctly signed by a bundle key but with no `signature.public_key`, **when** `verifyReceipt` runs, **then** `valid` is false with error `signature.public_key: required string`.
- **Given** one with no `receipt_id` (or a non-string one), **then** `valid` is false with error `receipt_id: required string`.
- **Given** one whose payload holds `1.5`, **then** `valid` is false (`number 1.5 is not a JS-safe integer`).
- **Given** its JSON text repeats a member name, **when** `verifyReceiptJson(text)` runs, **then** `valid` is false (`duplicate key …`).

### US2 — The tier ceiling always applies (R002)
- **Given** a hand-built bundle whose key has no `attestation_strength`, **when** a receipt signed by it claims `software`, **then** `valid` is false with `attestation_strength ceiling violated: receipt=software > key=(none, treated as self-asserted)`.
- **Given** the same receipt claims `self-asserted`, **then** it verifies.

### US3 — One canonicalizer (R003)
- **Given** `scripts/verdict-lib/jcs.js`, **then** its `canonicalize`/`canonicalizeBytes` are the very functions exported by `dist/index.js` (`===`), and every `test/vectors/jcs.json` vector still produces its frozen bytes through every import path.

### US4 — The log key cannot be the receipt key once a log key is pinned (R004)
- **Given** `logKeys` = `[tm-receipt key]` only (today), **then** inclusion verifies exactly as today and `result.log.log_key === "shared_with_receipts"`.
- **Given** `logKeys` = `[dedicated log key, receipt key]`, **then** the call fails at key load with `log key <id> is also a receipt-signing key`, before any STH is checked.
- **Given** `logKeys` = `[dedicated log key]` and an STH signed by the receipt key, **then** the STH is rejected and `log_key === "separate"`.

### US5 — Shared vectors (R005)
- **Given** `test/vectors/receipt-v1/`, **then** it holds `cases.json` plus one raw receipt file per case, and `node --test` runs every case through `verifyReceiptJson` and gets the named verdict. The Rust run reads the same files with no edits.

## Functional Requirements

- **FR-001** `verifyReceipt` errors when `signature.public_key` is absent or not a string, and when `receipt_id` is absent or not a string. Error strings: `signature.public_key: required string`, `receipt_id: required string`.
- **FR-002** In the ceiling check (`src/index.ts` step 5), a signing key without `attestation_strength` ranks as `self-asserted` (0). A key whose field is present but not a tier keeps ranking −1 (today's rule). `unsafeSkipStrengthCeiling` still skips.
- **FR-003** `scripts/verdict-lib/jcs.js` re-exports `canonicalize` and `canonicalizeBytes` from `../../dist/index.js`; it keeps exporting `uuidv7` (used by `test/_helpers.mjs:10`). `verify-log.mjs` per Q2.
- **FR-004** Log key separation per Q1: `SthOptions.receiptKeys`, the shared/separate decision, the load-time refusal, and `log_key: "shared_with_receipts" | "separate"` on `SthResult`, `InclusionResult` and `VerifyResult.log` whenever log keys were evaluated. `VerifyResult.log` without `inclusion` stays `{ status: 'not_checked' }`.
- **FR-005** `verifyReceipt` errors on any number in the receipt that is not `Number.isSafeInteger`, unless `unsafeAllowNonIntegers` (Q3). The verdict kernel passes the option.
- **FR-006** New export `verifyReceiptJson(text: string, opts?)`: strict parse (duplicate member name → `valid:false`, error `duplicate key "<name>"`; any other parse error → `valid:false`, error `receipt JSON: <message>`), then `verifyReceipt`. Never throws.
- **FR-007** `test/vectors/receipt-v1/` holds `cases.json` and one raw `<case>.json` per case. Case names and expected verdicts (exact strings): `valid`, `unknown_key`, `expired_key`, `revoked_key`, `tier_too_high`, `missing_public_key`, `missing_receipt_id`, `float_payload`, `duplicate_key`, `bad_timestamp`. Only `valid` verifies. Each invalid case carries exactly one defect.
- **FR-008** The fixtures are produced by a committed, deterministic generator from a test-only Ed25519 seed that is labelled as public test material and used for nothing else. Re-running it reproduces every file byte-for-byte.
- **FR-009** "Tollbooth" → "Fareseal" in the 4 prose mentions (no identifier or signed value exists to keep).
- **FR-010** `package.json` and `package-lock.json` version `3.0.0`; CHANGELOG has a `## 3.0.0 — unreleased` section whose **Breaking** list names FR-001, FR-002, FR-004 (separate mode), FR-005.

## Success Criteria

- **SC-1** `npm run build && npm test` passes; test count ≥ 132 (today's) + the new tests; 0 failures.
- **SC-2** `grep -rni tollbooth --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=specs .` prints nothing.
- **SC-3** `node -e` check: `import('./scripts/verdict-lib/jcs.js')` `.canonicalize === import('./dist/index.js').canonicalize` is `true`.
- **SC-4** `ls test/vectors/receipt-v1/*.json | wc -l` = 11 (manifest + 10 cases); the vector test reports 10 passing cases.
- **SC-5** Re-running the generator leaves `git status --porcelain test/vectors/receipt-v1` empty.
- **SC-6** `node -p "require('./package.json').version"` prints `3.0.0`; nothing is published (`npm view @tunnelmindai/receipt-verify version` still 2.0.0 — the owner checks).
- **SC-7** CI (`.github/workflows/test.yml`, Node 20/22/24) green on the PR.

## Edge Cases

- `public_key: ""` → string, so FR-001 passes it; the bundle comparison (`src/index.ts:275`) then fails it as a mismatch. `receipt_id: ""` is a string and passes FR-001 (matches Rust `:186`, which only checks the type).
- `allowKeyMismatch` with no embedded `public_key`: FR-001 errors first; no alternative key is searched (there is nothing to match).
- Key `attestation_strength: null` → treated as missing → `self-asserted`.
- `9007199254740993` in the text parses to `2^53`, which is not a safe integer → rejected (matches Rust, `MAX_SAFE = 2^53-1`). `-0` is a safe integer → accepted.
- Duplicate keys in nested objects and in `signature` are refused too; duplicate *values* in arrays are fine.
- Separate mode with a `logKeys` entry whose status is `revoked`: `usable()` already ignores it; it does not count toward either mode.
- `verifySth` called with `receiptKeys: []` → nothing is a receipt key → separate mode, no refusal (caller opted out explicitly).
- `bad_timestamp` vector uses a value every engine rejects (`"not-a-timestamp"`), not a `Date.parse`-lenient one (RV-5 is out of scope).

## Assumptions

- "Lowest tier" = `self-asserted` (`STRENGTH_RANK` rank 0, `src/index.ts:46-51`).
- Verdict names are snake_case forms of the prompt's case list; the sibling Rust run uses the same `cases.json`.
- The fixtures' keys, timestamps and revocation feed live inside `cases.json`, so no case depends on the clock.
- The CHANGELOG's current `## Unreleased` entries become part of 3.0.0.

## Out of Scope

- Publishing to npm (R006, owner).
- The Rust side of the vectors (sibling run in `rune`).
- RV-3 (verdict kernel witness quorum), RV-4 (timestamp proofs), RV-5 (strict RFC 3339), RV-7 (script verifier disagreements), RV-8 (weak `requireKeyId` default), RV-9 (osv-scanner pin), the Merkle-verifier triplication.
- Giving the live log its own key (that is a data-api sequencer change).
- Any deploy, host, Cloudflare, Supabase or DNS change.
