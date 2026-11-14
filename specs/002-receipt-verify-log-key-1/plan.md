# Plan — receipt-verify-log-key-1

## Constitution check

No `.specify/memory/constitution.md` and no `.specify/templates/` or `templates/overrides/` in this repo (same as spec 001), so no ADR-before-code rule of this repo applies. The design ADR is the Data API's ADR-047 (another repo, read only). The prompt itself sets a GATE 0: the coordinator approves the four-point plan below before any code. Rules from the prompt and house rules:
- Tests first, in the same task as the change; no network in tests; TEST keys generated inside the tests only.
- Behaviour not named here stays byte-identical (every 3.0.0 call form).
- No key or secret generated, read or handled outside tests; only PUBLIC keys already published (`tm-receipt-2026-05` in `src/pinned-keys.ts`).
- No push, PR, merge, publish or deploy by an agent. One DRAFT PR, opened by the coordinator after GATE F, merged only on the owner's word.
- Conventional Commits; no machine names, local paths or personal names in tracked files or commit messages.

## Verify command (every task)

```
npm run build && npm test
```

(`npm test` = `node --test test/*.test.mjs`; tests import `dist/`, so build first. Baseline at 1b6edd2: 168 pass, 0 fail. CI: `.github/workflows/test.yml`, Node 20/22/24.)

## GATE 0 plan (the four points the prompt asks for)

### (1) Every place in this repo that verifies or displays a tree head or names its key

| Where | What it does today | Change |
|---|---|---|
| `src/log.ts:1-36` | header: dialect, "live log signs with tm-receipt-2026-05", shared/separate modes, time windows | add the key-document mode and the tree-size rule |
| `src/log.ts:87-124` | `LogKeyEntry`, `SthOptions`, `SthResult`, `InclusionResult` types | add `LogKeyDoc` / `LogKeyDocEntry` / `LogKeyHandover`; `reason?` on `SthResult` |
| `src/log.ts:152-167` | `logKeyMode` (shared vs separate, mixed-set refusal) | untouched in array mode; document mode reports mode from the selected entry |
| `src/log.ts:179-268` | `verifySth` — pinned array only, `key_id` select, `log_id` bind, `keyUsableAt` time window (`:230-237`) | branch: a document → ADR-047 §7 rules |
| `src/log.ts:282-344` | `verifyReceiptInclusion` (calls `verifySth` at `:307`) | accept a document |
| `src/log.ts:356-420` | `verifySthConsistency` (two `verifySth` calls `:371-372`) | accept a document (heads may be under different keys) |
| `src/log.ts:469-538` | `LogMonitor` (constructor `:477-486` checks `logKeyMode`; `observeNow` `:501`) | accept a document; check it at construction |
| `src/keys.ts:108-128` | `keyUsableAt` (time window; `'sth'` subject) | unchanged; not used in document mode |
| `src/pinned-keys.ts:8-42` | `PINNED_KEY_BUNDLE` — the receipt key `tm-receipt-2026-05`, the anchor | add `PINNED_LOG_KEYS` next to it |
| `src/index.ts:135-147` | `VerifyOptions.inclusion.logKeys: LogKeyEntry[]` | type widens to `LogKeyEntry[] \| LogKeyDoc` |
| `src/index.ts:166` | `VerifyResult.log` (`log_key_id`, `log_key`) | unchanged shape |
| `src/index.ts:471-492` | step 8, inclusion via `verifyReceiptInclusion` | passes the document through |
| `src/index.ts:525-565` | re-exports of log API and types | add `checkLogKeyDoc`, `PINNED_LOG_KEYS`, `LOG_KEYS_URL`, new types |
| `scripts/verify-log.mjs:1-32` | header/usage | Data API usage lines, lineage note (this is upstream) |
| `scripts/verify-log.mjs:133-144` | `verifySth(sth, pub)` (one pinned key) | unchanged |
| `scripts/verify-log.mjs:146-212` | CLI `inclusion` (`:162-180`), `consistency` (`:181-203`, stricter than the Data API's), `sth` (`:204-208`) | add `--receipt-key/--allow-shared`, `--log-keys`, `handover`; `--log-keys` on inclusion/consistency |
| `scripts/verdict-lib/verify-receipt.js:110-131` | `checkpoint_signature` on verdict-receipt checkpoints (`--log-key`) | NOT a receipt-log tree head (the issuer leaves checkpoints unsigned); unchanged, out of scope |
| `README.md:144-213`, `:220-240`, `:282` | library log section ("The live log signs tree heads with tm-receipt-2026-05", `logKeys` example `:153-159`), CLI section | rewrite for both states |
| `ARCHITECTURE.md:13`, `:41-42`, `:62-66` | log trust model ("Today the live log signs with the receipt key") | add the document + anchor |
| `CHANGELOG.md` | top section | `## 3.1.0 — unreleased` |
| `test/log.test.mjs:194-260`, `:489-530` | `signSth` helper, array-mode `verifySth` tests, live-dialect test | add document-mode tests; existing tests unchanged |
| `test/cli.test.mjs:204-335` | `verify-log.mjs` CLI tests | add new-mode tests; existing unchanged |

### (2) The ADR-047 rule this repo implements

Trust: the pinned receipt key (`PINNED_KEY_BUNDLE`, or `--receipt-key`) anchors `keys[0]`; each later entry is trusted only through its hand-over, signed by the previous entry's key. That is ADR-047 §4 ("receipt-verify pins the document … `PINNED_LOG_KEYS`, with tree-size ranges replacing the time window") plus §7 rule 3 and the Data API `checkSthKey` anchor (`first_key_not_pinned`). A document from anywhere (the pin, or the served file) is accepted only after that check, so a caller-supplied document cannot add trust the receipt-key pin does not already give.

Document check (`checkLogKeys` / `checkLogKeyDoc`), first failure wins, same strings as the Data API: `bad_doc`, `bad_entry` (also non-standard base64 here), `bad_key_id` (after the first: `^tm-log-[0-9]{4}-(0[1-9]|1[0-2])$`), `bad_range` (from = previous until, first from 0, until > from, only the last open), `handover_missing`, `handover_on_first_entry`, `bad_handover` (type `tunnelmind.log-key-handover/v1`, 32-byte hex root), `handover_replay`, `handover_log_id`, `handover_from_key`, `handover_to_key` (id and key bytes), `handover_tree_size` (= entry `from_tree_size`), `handover_signature` (Ed25519 over JCS(hand-over minus signature) under the previous entry's key), `duplicate_key_id`; then `first_key_not_pinned`.

Head check (`checkSthKey` / `verifySth(sth, doc)`), in the Data API order: `invalid_key_doc`, `first_key_not_pinned`, `no_signature` (no `signature.key_id`), `log_id_mismatch`, `key_id_mismatch` (top-level ≠ signature), `unknown_key_id` (never try every key), `key_id_missing` (handed-over entry, no top-level `key_id` — ADR-047 §5), `public_key_mismatch`, `bad_signature`, `tree_size_out_of_range` (the tree-size validity rule: `from ≤ size ≤ until`, null = open; replaces the time window), `root_mismatch` (at a boundary size, under either key, root = hand-over root).

Refused: everything above. Not refused, by design (ADR-047 §8): a receipt-key head at size ≤ m with a valid signature; the README and LogMonitor's consistency check are the defence.

### (3) Behaviour today and after the cut-over, and the test vectors

| State | Document in use | Head | Result |
|---|---|---|---|
| Today (shared) | `PINNED_LOG_KEYS` (one entry, receipt key, open) | live-dialect head under the receipt key, any size | valid, `shared_with_receipts` |
| Today | `PINNED_LOG_KEYS` | head naming `tm-log-*` | `unknown_key_id` |
| After, caller passes the served document | doc: receipt key [0, m], log key [m, null] + hand-over | log-key head n ≥ m, signed `key_id` | valid, `separate` |
| After | same | receipt-key head n > m | `tree_size_out_of_range` |
| After | same | either key at m, root ≠ hand-over root | `root_mismatch` |
| After, stale pin | `PINNED_LOG_KEYS` unchanged | log-key head | `unknown_key_id` (the README's reason to pass the served doc or extend the pin) |
| After, owner extended the pin | `PINNED_LOG_KEYS` = served doc | log-key head | valid |

Test vectors are built in the tests: two Ed25519 pairs from `webcrypto.subtle.generateKey` (test "receipt" key and test "log" key, plus an attacker key), a test hand-over signed by the test receipt key over a test tree at m, documents built from them. The receipt key used as anchor in these tests is passed explicitly (`receiptKeys` / `--receipt-key`), never the real pin, except for the one test that checks `PINNED_LOG_KEYS` against `PINNED_KEY_BUNDLE` (no signature needed: a one-entry document has no hand-over). Library and CLI run the same vector list and must give the same reason (FR-008).

### (4) What the owner does after the ceremony, and the check-after

Nothing is required for correctness: a caller that passes the served document gets own-key heads verified the moment it is published. Recommended, one PR: replace the `PINNED_LOG_KEYS` literal in `src/pinned-keys.ts` with the served document (a pasted JSON value, the same way `PINNED_KEY_BUNDLE` is refreshed), bump `PINNED_LOG_KEYS_FETCHED_AT`, release. Check-after: `npm test` green, and `node scripts/verify-log.mjs handover <pinned-copy.json> --receipt-key=<receipt-pub>` prints `{"valid":true,"reason":null}`, and `node scripts/verify-log.mjs sth sth.json --log-keys <pinned-copy.json> --receipt-key=<receipt-pub>` on the live head prints `valid: true` with `key_id` `<id>`.

## Approach

- **CLI first (T001, T002)**: port `checkLogKeys`/`checkSthKey` and the CLI branches from the Data API copy, but keep this file's stricter parts (three-argument `consistency`, `isB64`, no throws). Use `isB64` inside `is32`/`sameKey` so a base64url key cannot pass. Header: this file is upstream again; note "Data API delta of 2026-11-10/11 carried upstream".
- **Library (T003–T005)**: in `src/log.ts`, no new file. A document is recognised by shape (`!Array.isArray(x) && typeof x === 'object' && Array.isArray(x.keys)`); one private `docCheck` used by `verifySth` and the constructor; Ed25519 via the existing `ed25519Verify` (`:130`), canonical bytes via `canonicalizeBytes`, hashes via `parseHash`/`bytesEqual`. `PINNED_LOG_KEYS` + `PINNED_LOG_KEYS_FETCHED_AT` + `LOG_KEYS_URL` live in `src/pinned-keys.ts`.
- `ponytail:` no fetch helper in the library; README shows the three-line fetch-else-pin pattern. Add one if callers ask.

## Risks

- **Two verifiers drifting.** Mitigated by FR-008's agreement test over every vector.
- **Pin staleness after the cut-over** (receipt-key heads above m pass under a stale pin). Documented; the owner's PR closes it; `LogMonitor` consistency still catches forks.
- **Base64 laxness** in `Buffer.from` (Data API `is32`): fixed here by `isB64`; the closeout lists it as a delta for the Data API's next re-vendor.
- **Type widening** of `logKeys` is additive; TypeScript callers that pass arrays compile unchanged.
- **Wrong order of checks** would give different reasons in library and CLI; the agreement test catches it.
