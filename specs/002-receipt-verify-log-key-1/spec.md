# Spec — receipt-verify-log-key-1: teach the public verifier the log key

**Intent.** Bring this repo's transparency-log verifier (the library `src/log.ts` and the CLI `scripts/verify-log.mjs`) in line with the Data API's reference verifier and ADR-047: a pinned key document (`PINNED_LOG_KEYS`), hand-over verification anchored on the already-pinned receipt key, and the tree-size validity rule. It must ship before the owner's key ceremony and be correct both today (shared mode: tree heads signed by the receipt key `tm-receipt-2026-05`) and after the cut-over (own log key `tm-log-YYYY-MM`), with no second release.

Source prompt (owner, 2026-11-14), key sentences:

> "receipt-verify PINNED_LOG_KEYS, plus the tree-size validity rule and the upstream verify-log.mjs delta (this repo's copy diverges from its vendored source until then). Must ship before step 5."

> "Bring this repo's verifier in line with the Data API's scripts/verify-log.mjs (sth, consistency and inclusion checks; --log-keys, --receipt-key, --allow-shared behaviour; a key-document entry after the first without a hand-over is refused; a hand-over's signature must verify under the previous key), add the pinned log key list (empty of log keys today; the receipt key pin stays), and the tree-size validity rule."

> "A verifier that pins only the receipt key must not say "invalid" for the first own-key head once the owner has extended the pin or the hand-over chain verifies."

> "nothing may be hard-coded that needs it [the new log public key]; design for a pinned-key list that the owner extends in a one-line follow-up PR after the ceremony, or for trust chained from the already-pinned receipt key through the signed hand-over (ADR-047 says which is allowed: follow it, do not invent)."

Sources of truth (read only, other runs own them): Data API `docs/adr/ADR-047-log-key-life.md` (§4 key document, §5 signed `key_id`, §6 hand-over record, §7 verifier rule, §8 pre-cut-over heads), `docs/LOG-KEY-RUNBOOK.md` ("Every place that must learn the new public key"), `scripts/verify-log.mjs` (`checkLogKeys`, `checkSthKey`, CLI modes), `api/roots/pinned-keys.json`. Draft PR tunnelmind-data-api#123 changes the runbook pre-check (looks the key up by the head's own `signature.key_id`) and `log-key-handover.mjs` URL shapes; its `verify-log.mjs` is byte-identical to main. This spec builds against the #123 versions (the stricter ones); the closeout says so.

Observed 2026-11-13: `GET https://data.tunnelmind.ai/.well-known/receipt-log-keys.json` → 404 (shared mode, no key document published).

## User Scenarios

### US1 — A verifier today (shared mode) keeps working (P1)
A caller verifies a live tree head signed by `tm-receipt-2026-05` (`signature.key_id` set, no top-level `key_id`, `log_id` `tunnelmind-receipts-log-v1`).
- **Given** `PINNED_LOG_KEYS` (one entry: the receipt key, `from_tree_size` 0, `until_tree_size` null), **when** `verifySth(sth, PINNED_LOG_KEYS)` runs, **then** `valid: true`, `key_id: 'tm-receipt-2026-05'`, `log_key: 'shared_with_receipts'`.
- **Given** the CLI, **when** `verify-log.mjs sth sth.json --log-keys doc.json --receipt-key=<receipt-pub>` runs on the same head and a one-entry document, **then** it prints `{"valid":true,"key_id":"tm-receipt-2026-05","reason":null}` and exits 0.
- Every existing call form (`verifySth(sth, [entries])`, `sth <sth> <pub>`, `inclusion … --key`, `consistency … --key`) behaves exactly as at 3.0.0.

### US2 — After the cut-over, the first own-key head verifies without a new release (P1)
The owner has published a key document whose second entry `tm-log-YYYY-MM` carries a hand-over signed by the receipt key at size m.
- **Given** that document (fetched by the caller, or pinned), **when** a head of size n ≥ m signed by the log key (top-level `key_id` = `signature.key_id`) is verified, **then** it is valid and `log_key: 'separate'`, because the document's chain is anchored on the pinned receipt key and the hand-over verifies under it.
- **Given** the same document, **when** a receipt-key head with `tree_size` > m is verified, **then** it is refused (`tree_size_out_of_range`).
- **Given** a head at exactly m, **when** its `root_hash` differs from the hand-over's `root_hash`, **then** it is refused (`root_mismatch`), whichever key signed it.
- **Given** a consistency proof from a receipt-key head ≤ m to a log-key head > m, **when** `verifySthConsistency(older, newer, proof, doc)` or `verify-log.mjs consistency … --log-keys doc --receipt-key=…` runs, **then** it verifies.

### US3 — A forged or broken key document is refused (P1)
- An entry after the first without `handover` → `handover_missing`; a hand-over not signed by the previous entry's key → `handover_signature`; a second hand-over to the same `to_key_id` → `handover_replay`; `keys[0]` not the pinned receipt key → `first_key_not_pinned`; a stray or malformed field per ADR-047 §4/§7 → the matching reason. In every case no head verifies under that document.

### US4 — The owner extends the pin after the ceremony (P2)
- **Given** the served document, **when** the owner (or a later run) replaces `PINNED_LOG_KEYS` with it in one PR, **then** `npm test` passes unchanged (the pinned-document test checks shape and anchor, not entry count) and `verify-log.mjs handover` on the pinned copy exits 0.

## Functional Requirements

- **FR-001** `scripts/verify-log.mjs` gains the Data API delta: `sth <sth> <pub> --receipt-key=<b64> [--allow-shared]` (reports `log_key` `own|shared_with_receipts`, shared exits 1 unless `--allow-shared`), `sth <sth> --log-keys <doc> --receipt-key=<b64>`, `handover <doc> --receipt-key=<b64>`, with `checkLogKeys` and `checkSthKey` exported and returning the same reason strings as the Data API copy. `--receipt-key` is required with `--log-keys` and `handover` (exit 2 without).
- **FR-002** This repo's stricter behaviour is kept where the Data API copy is weaker: the three-argument pinned `consistency` form (roots from the two signed heads), the standard-base64 guard (`isB64`) also applied to every key/signature the new code decodes, and "returns false, never throws" on malformed input.
- **FR-003** `inclusion` and `consistency` accept `--log-keys <doc> --receipt-key=<b64>` in place of `--key`, checking each head with `checkSthKey` (so a consistency proof can span the cut-over). Without `--log-keys` their behaviour is unchanged.
- **FR-004** `src/pinned-keys.ts` exports `PINNED_LOG_KEYS`: an ADR-047 §4 key document with `log_id` `tunnelmind-receipts-log-v1` and exactly one entry, the receipt key `tm-receipt-2026-05` (same `public_key` as `PINNED_KEY_BUNDLE`), `from_tree_size` 0, `until_tree_size` null, `shared_with_receipts` true. No `tm-log-*` key or placeholder for one.
- **FR-005** `src/log.ts` exports `checkLogKeyDoc(doc, receiptKeys?)` → `null` or a reason string, implementing ADR-047 §7 rule 3 (contiguous ranges, `until > from`, only the last open, key-id pattern `^tm-log-[0-9]{4}-(0[1-9]|1[0-2])$` after the first, hand-over on every later entry and never on the first, hand-over fields and Ed25519 signature under the previous entry, no replay, unique ids) plus the anchor: `keys[0].public_key` equals (decoded bytes) a non-revoked receipt key from `receiptKeys` (default `PINNED_KEY_BUNDLE.keys`), else `first_key_not_pinned`.
- **FR-006** `verifySth(sth, logKeys, opts)` accepts either today's `LogKeyEntry[]` (unchanged behaviour, time windows) or a key document. With a document it applies ADR-047 §7 rules 1–6 in the CLI's order: document valid and anchored; `signature.key_id` present and in the document (unknown → refused, never "try every key"); `sth.log_id` = document `log_id`; top-level `key_id`, if present, = `signature.key_id`, and required for a handed-over entry; `signature.public_key`, if present, = the entry's; Ed25519 over `JCS(sth minus signature)` under the entry's key; `from_tree_size ≤ tree_size ≤ until_tree_size` (null = open); at a boundary size the head's root = the hand-over root. The tree-size range replaces the time window in document mode. The result carries `reason` (the same string the CLI prints) and `log_key` (`shared_with_receipts` for `keys[0]`, `separate` for a handed-over entry).
- **FR-007** `verifyReceiptInclusion`, `verifySthConsistency`, `LogMonitor` and `verifyReceipt({ inclusion: { logKeys } })` accept a key document wherever they accept `LogKeyEntry[]`. `LogMonitor` throws at construction if the document fails `checkLogKeyDoc` or its `log_id` ≠ the monitor's `logId`.
- **FR-008** Library and CLI agree: for every test vector, `verifySth(sth, doc).reason` equals `checkSthKey(sth, doc, receiptPub)` and `checkLogKeyDoc(doc)` equals `checkLogKeys(doc)` (or `first_key_not_pinned`).
- **FR-009** README, ARCHITECTURE and CHANGELOG describe both states, the fetch-or-pin choice, the ADR-047 §8 residual risk, and the owner's post-ceremony step. Version 3.0.0 → 3.1.0 (additive).
- **FR-010** No network in tests; every key in tests is generated inside the test run; no `tm-log-*` public key is committed anywhere.

## Success Criteria

- **SC-001** `npm run build && npm test` passes; total test count > 168 (baseline at 1b6edd2: 168 pass, 0 fail), 0 fail.
- **SC-002** New tests exist and pass by name: shared-mode head valid under `PINNED_LOG_KEYS`; own-key head valid under a test document with a test hand-over; each refusal reason in US2/US3 (at least: `handover_missing`, `handover_signature`, `handover_replay`, `first_key_not_pinned`, `unknown_key_id`, `key_id_missing`, `tree_size_out_of_range`, `root_mismatch`, `log_id_mismatch`); cross-cut-over consistency; library/CLI agreement over the whole vector set.
- **SC-003** `grep -rn "tm-log-[0-9]" src/ scripts/` finds only the key-id regex, no key entry; `grep -rnE "fetch\(|https?://" test/*.test.mjs` adds no network call.
- **SC-004** `node scripts/verify-log.mjs handover <PINNED_LOG_KEYS as JSON> --receipt-key=U18ONQCXr/Ox3Ac1ShKB1zYRcPIM9Sp9yZrka1jzoCY=` prints `{"valid":true,"reason":null}` and exits 0 (run inside a test).
- **SC-005** Every 3.0.0 test in `test/log.test.mjs` and `test/cli.test.mjs` passes unedited, except where a task names the edit and why.
- **SC-006** `git diff --stat main` touches only: `scripts/verify-log.mjs`, `src/log.ts`, `src/pinned-keys.ts`, `src/index.ts`, `test/log.test.mjs`, `test/cli.test.mjs`, `README.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `package.json`, `package-lock.json`, and this spec directory.

## Edge Cases

- Head at exactly m signed by the receipt key (allowed: both keys may sign m) and by the log key: both must carry the hand-over root.
- `until_tree_size` = `from_tree_size` (zero width) → `bad_range` (Data API review N5).
- Key document where `keys[0].key_id` is not `tm-receipt-2026-05` but the bytes are the pinned receipt key: accepted (the CLI anchors on bytes, as ADR-047 §7 says "under any id").
- A base64url or junk-padded key or signature in the document → refused (FR-002), where `Buffer.from(…, 'base64')` alone would accept it.
- A receipt-key head with no `signature.key_id` (legacy dialect) under a document → `no_signature`, as the CLI. Array mode still allows it.
- Live heads carry `root_hash` with a `0x` prefix; the hand-over root does too: compare decoded bytes.
- A stale pin (`until_tree_size` null) after the cut-over still accepts receipt-key heads above m. That is ADR-047 §8's residual plus staleness; the README says to prefer the served document once it exists and to extend the pin.
- A served document that fails the check is treated as absent (ADR-047 §4): the README pattern falls back to `PINNED_LOG_KEYS`, never to "trust the head".
- Rollback (runbook step 6): receipt-key heads above m are flagged invalid under the published document. Correct per the runbook; documented, not worked around.

## Assumptions

- ADR-047 is the design as merged on the Data API main; §7 and the Data API `checkLogKeys`/`checkSthKey` are the rule. Where they differ in detail, the code (`checkSthKey`) wins, because that is what the runbook's checks run.
- Trust for an own-key head comes from the chain: pinned receipt key → `keys[0]` → each hand-over signature. ADR-047 §4 says a pinned copy is what a careful verifier trusts; §7 makes a document checkable against the receipt-key pin. Both are supported: the pin is the default, a caller-supplied document is accepted only after the same anchored check. Nothing new is invented.
- The library does not fetch the key document (offline-first, zero network in the default path). It exports the URL; the README shows the fetch.
- `verifyReceipt`'s `inclusion.logKeys` stays required (no default to `PINNED_LOG_KEYS`): defaulting would turn today's "no pinned log key" error into a pass for callers who omitted it. The coordinator may flip this at GATE 0.
- Re-vendoring this file back into the Data API is that repo's work (another run).

## Out of Scope

- Generating, reading or handling any private key; any production read or write beyond the one public GET above; deploys; npm publish (owner); the site mirror (`site-log-key-1`); any change in tunnelmind-data-api; break notices (ADR-047 §10, not defined yet); log-to-log rotation code (§9, the document shape already covers it); outside witnesses (§11); `scripts/verdict-lib/verify-receipt.js` `checkpoint_signature` (verdict checkpoints, not the receipt log's tree heads; unchanged).
