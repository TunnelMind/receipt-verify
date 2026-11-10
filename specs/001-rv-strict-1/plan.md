# Plan — rv-strict-1

## Constitution check

No `.specify/memory/constitution.md` and no `.specify/templates/` or `templates/overrides/` in this repo, so no ADR gate. The rules that apply come from the prompt and the house rules:
- Tests and their fix go in one task; behaviour not named here stays byte-identical.
- No publish, deploy, push, host/DNS/Cloudflare/Supabase change, history rewrite. Publishing is the owner task T011.
- No secret in code, tests, logs, commits. The vector generator's Ed25519 seed is **public test material** (derived from a fixed public string, labelled as such, used for nothing else). It is not a secret.
- GATE 0 first, because Q1–Q6 in spec.md change what gets built. The tasks follow the recommended defaults; if Josh changes an answer, the coordinator re-plans only the tasks that answer touches (Q1→T005, Q2→T004, Q3→T006, Q4→T007, Q5→T008, Q6→T001).

## Verify command (every task)

```
npm run build && npm test
```

(`npm test` = `node --test test/*.test.mjs`, and the tests import `dist/`, so the build must run first. Baseline at f69fc1d: 132 pass, 0 fail.)

## Where the change goes

| Item | Files | What |
|---|---|---|
| R007 rename | `ARCHITECTURE.md:22`, `README.md:252`, `test/jcs-vectors.test.mjs:3`, `test/vectors/jcs.json:3`, `CHANGELOG.md` | prose only; note jcs.json's new sha256 in CHANGELOG |
| R001 | `src/index.ts` (after step 1, before step 3), `test/verify.test.mjs`, `CHANGELOG.md` | two type checks; `Receipt` type already declares both fields required |
| R002 | `src/index.ts:326-344` (step 5), `test/_helpers.mjs` or the bundle literals in `test/verify.test.mjs`, `test/cli.test.mjs`, `test/properties.test.mjs`, `test/log.test.mjs`, `CHANGELOG.md` | `rankOf(signingKey.attestation_strength ?? 'self-asserted')`; drop the `signingKey?.attestation_strength &&` guard, keep `signingKey &&` |
| R003 | `scripts/verdict-lib/jcs.js`, `test/jcs-vectors.test.mjs`, `README.md:252`, `ARCHITECTURE.md` | re-export from `../../dist/index.js` (pattern: `scripts/verdict-lib/hash.js:17`); keep `uuidv7` |
| R004 | `src/log.ts` (`SthOptions`, `SthResult`, `InclusionResult`, `verifySth`, `verifyReceiptInclusion`, `verifySthConsistency`, `LogMonitor` constructor, header comment `:19-24`), `src/index.ts` step 8 + `VerifyResult.log` type, `test/log.test.mjs`, `README.md` log section, `CHANGELOG.md` | one helper `logKeyMode(logKeys, receiptKeys)` → `{ mode, clash? }`, called once per entry point |
| R005a floats | `src/index.ts` (new check + `unsafeAllowNonIntegers` in `VerifyOptions`), `scripts/verdict-lib/verify-receipt.js:79`, `test/verify.test.mjs`, `test/properties.test.mjs` (the verify-property generator at `:120` must emit safe integers; the canonicalize properties keep floats), `CHANGELOG.md` | recursive walk, mirrors Rust `check_numbers` |
| R005b dup keys | `src/jcs.ts` (strict parser next to the canonicalizer — no new file), `src/index.ts` (`verifyReceiptJson` + export), `test/verify.test.mjs`, `README.md` API list, `CHANGELOG.md` | small recursive-descent scanner that only tracks member names and delegates value parsing to `JSON.parse` of the whole text after the scan passes |
| R005 vectors | `scripts/gen-receipt-v1-vectors.mjs`, `test/vectors/receipt-v1/cases.json` + 10 `<case>.json`, `test/receipt-v1-vectors.test.mjs`, `README.md`, `ARCHITECTURE.md` | generator imports only `node:` builtins + `dist/jcs.js`; deterministic Ed25519 (seed → PKCS8 DER via the fixed 16-byte prefix) |
| Major bump | `package.json`, `package-lock.json` (both `version` fields), `CHANGELOG.md` | 2.0.0 → 3.0.0, heading `## 3.0.0 — unreleased` + **Breaking** list |

### `cases.json` shape (the cross-language contract)

```json
{
  "about": "Receipt v1.0 cross-implementation vectors: receipt-verify (JS) and rune-record (Rust) read these files unchanged. …",
  "seed_note": "test-only key material, public, never used to sign anything real",
  "keys": { "keys": [ { "key_id": "vec-valid", …, "attestation_strength": "software" },
                      { "key_id": "vec-expired", …, "rotation_after": "2026-01-01T00:00:00Z" },
                      { "key_id": "vec-revoked", … } ] },
  "revocations": { "feed_version": 1, "revoked_keys": [ { "key_id": "vec-revoked", "reason": "compromise", … } ], "revoked_receipts": [] },
  "cases": [ { "name": "valid", "file": "valid.json", "expect": "valid" }, … ]
}
```

Each `<case>.json` is the receipt's raw bytes (so `duplicate_key.json` really has a repeated member). All timestamps are fixed. JS test: read text → `verifyReceiptJson(text, { keys, revocations, noFetchKeys: true })` → map errors to a verdict name with a small regex table in the test → `assert.equal(name, case.expect)`, and each invalid case has exactly one error.

## Approach and order

1. GATE 0 (Josh answers Q1–Q6).
2. T001 rename — prose only, independent.
3. T002 R001, T003 R002 — small `src/index.ts` edits; both touch `test/verify.test.mjs`, so they run one after the other.
4. T004 R003 — scripts + test only, parallel-safe with T002/T003.
5. T005 R004 — `src/log.ts`, plus step 8 of `src/index.ts`.
6. T006 floats, T007 `verifyReceiptJson`.
7. T008 vectors — needs T002, T003, T006, T007, since every case's verdict comes from those.
8. T009 major bump + CHANGELOG heading.
9. T010 tell the Rust sibling run where the manifest is (a message from the coordinator; no repo change).
10. T011 (owner) publish. GATE F.

## Risks

- **Live receipts with floats (Q3).** If scry-server or data-api sign floats outside verdict receipts, 3.0.0 rejects them. That is why it is a GATE 0 question and a major bump; publishing stays with Josh.
- **R002 breaks many existing tests.** Most test bundles omit `attestation_strength` while `makeReceipt` claims `software` (`test/_helpers.mjs:28`). T003 must update them in the same task. Lazy route: `makeKeyBundle` fills `attestation_strength: 'software'` when an entry omits it, and the new missing-field test passes an explicit `attestation_strength: undefined`.
- **Hand-built bundles out in the world** (rune-record's conformance script `conformance.rs:34`) will start failing for non-`self-asserted` claims. That is intended (RV-2) and goes in the CHANGELOG Breaking list.
- **jcs.json sha churn (Q6).** Fareseal and atap pin its sha; the CHANGELOG line tells them to re-sync.
- **Deterministic signing:** Ed25519 is deterministic, but the generator must also fix `receipt_id`, timestamps and key order. SC-5 (regenerate → no diff) catches drift.
- **R004 scope creep:** only the mode decision and refusal. No new log-key bundle loader and no shipped `PINNED_LOG_KEYS`: none exists yet, so YAGNI.
- **Byte-identical rule:** the result object only gains fields (`log.log_key` when inclusion ran). No existing error string changes, except the ceiling message for a missing key strength, which used to be no message.

## Closeout notes for the coordinator

- All six cited findings were confirmed present at f69fc1d; none were skipped.
- The R003 nuance (only one canonicalizer is published; `verify-log.mjs` is independent on purpose) goes in the closeout whatever Q2's answer is.
