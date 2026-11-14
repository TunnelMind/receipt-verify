# Closeout — receipt-verify-log-key-1

Written for T007 on 2026-11-13, against the tree at commit 7821233 (branch
`crew/receipt-verify-log-key-1`, base 1b6edd2 on `main`). Every number and
file:line below was measured on that tree for this document; none is copied
from a task report.

The run's commits: T001 6dc240c, T002 e1924b3, T003 2ef5ca6, T004 9ec8da9,
T005 2ac7b06, T006 7821233.

## 1. What changed

### `scripts/verify-log.mjs` (the CLI, and the upstream of the Data API's vendored copy)

| Where | What | Commit |
|---|---|---|
| `:19-23` | usage lines for all five call forms | 6dc240c, e1924b3 |
| `:25-49` | lineage note (this file is upstream; the Data API delta of 2026-11-10/11 is carried here), `--receipt-key=` form, `sth --receipt-key`, key-document rules | 6dc240c |
| `:62-70` | header for `inclusion` / `consistency --log-keys` | e1924b3 |
| `:184-203` | key-document helpers: `isObj`, `isStr`, `isSize`, `is32` (`:195`) and `sameKey` (`:197`) with `isB64` inside, `isHex32`, `LOG_KEY_ID_RE` (`:200`), `sigOk` (`:203`) | 6dc240c |
| `:207-238` | `checkLogKeys(doc)`: reason string or `null`, first failure wins, never throws | 6dc240c |
| `:243-265` | `checkSthKey(sth, doc, receiptKeyB64)`: the head check, anchored on the receipt key at `:245` | 6dc240c |
| `:268-272` | `USAGE` | 6dc240c, e1924b3 |
| `:289-294` | `docMode`, `anchorOk`: exactly one of `--key` and `--log-keys`; `--log-keys` needs `--receipt-key` | e1924b3 |
| `:296-316` | `inclusion`: with `--log-keys` the head goes through `checkSthKey` (`:311`); output gains `reason` (`:314`) | e1924b3 |
| `:317-346` | `consistency`: each head checked on its own against the document (`:331-334`); roots and sizes still come from the two heads | e1924b3 |
| `:347-355` | `sth <sth> --log-keys <doc> --receipt-key=<b64>` | 6dc240c |
| `:356-363` | `handover <doc> --receipt-key=<b64>` | 6dc240c |
| `:364-378` | `sth <sth> <pub>` with `--receipt-key` / `--allow-shared`: reports `log_key`, shared exits 1 unless allowed, a malformed `--receipt-key` exits 2 (`:373`). Without `--receipt-key` the output is unchanged (`:366-369`) | 6dc240c |

`verifySth` (`:171-182`), `verifyInclusion`, `verifyConsistency`, `jcs` and
`isB64` (`:166`) are untouched. The file still imports only `node:crypto`,
`node:fs` and `node:util` (`:72-74`).

### `src/log.ts` (the library)

| Where | What | Commit |
|---|---|---|
| `:36-47` | header: the key document, key-document mode, and which callers take a document | 2ef5ca6, 9ec8da9, 2ac7b06 |
| `:105-136` | types `LogKeyHandover` (`:107`), `LogKeyDocEntry` (`:121`), `LogKeyDoc` (`:132`) | 2ef5ca6 |
| `:155-156` | `SthResult.reason` (document mode only) | 9ec8da9 |
| `:200` | `logKeyMode` parameter widened; a document has no mode here | 2ac7b06 |
| `:220-241` | helpers: `isObj`, `isStr`, `isHex32`, `LOG_KEY_ID_RE` (`:229`), `keyBytes` (`:234`), `key32` (`:238`) | 2ef5ca6 |
| `:250-257` | `checkLogKeyDoc(doc, receiptKeys?)`: awaits the collected hand-over signatures in document order, then returns the synchronous reason | 2ef5ca6, split in 2ac7b06 |
| `:266-327` | `checkLogKeyDocSync`: every rule except the signatures themselves; the anchor on a non-revoked receipt key at `:320-326` | 2ef5ca6, split in 2ac7b06 |
| `:337` | `isKeyDoc` type guard (how a document is told from a key array) | 9ec8da9 |
| `:339-396` | `verifySthDoc`: the head check in `checkSthKey`'s order; `log_key` set at `:361` | 9ec8da9 |
| `:403-413` | `verifySth`: doc comment, widened `logKeys` type (`:410`), dispatch to document mode before any array-mode code (`:413`) | 9ec8da9 |
| `:511-518`, `:540-542` | `verifyReceiptInclusion` accepts a document; `log_key` taken from the head check | 2ac7b06 |
| `:552-554` | rootless-head guard in `verifyReceiptInclusion` | 2ac7b06 |
| `:593-600` | `verifySthConsistency` accepts a document | 2ac7b06 |
| `:624-629` | rootless-head guard in `verifySthConsistency` | 2ac7b06 |
| `:703-705` | `LogMonitorOptions.logKeys` widened | 2ac7b06 |
| `:733-745` | `LogMonitor` constructor: throws `TypeError` on a document failing the synchronous rules (`:740-741`) or with `log_id` ≠ `logId` (`:742-744`) | 2ac7b06 |
| `:766-771` | rootless-head guard in `LogMonitor.observeNow`, before the store | 2ac7b06 |

Why the three rootless-head guards exist: document mode, like the CLI, checks
a head's `root_hash` only at a cut-over size. A validly signed head with an
unusable root could otherwise reach `bytesEqual` or the monitor's store.

The array-mode body of `verifySth` (`:414-498`) is unchanged.

### `src/pinned-keys.ts` (2ef5ca6)

- `:47` `LOG_KEYS_URL` = `https://data.tunnelmind.ai/.well-known/receipt-log-keys.json`
- `:53` `PINNED_LOG_KEYS_FETCHED_AT` = `'2026-11-13'` (the comment at `:49-52` says the document was written from ADR-047 §4, not copied, because the URL was not served on that date)
- `:55-66` `PINNED_LOG_KEYS`: `log_id` `tunnelmind-receipts-log-v1`, one entry, `tm-receipt-2026-05`, the same public key as `PINNED_KEY_BUNDLE`, from 0, open-ended, `shared_with_receipts: true`. No `tm-log-*` entry.

### `src/index.ts`

- `:38` `LogKeyDoc` type import; `:140-141` doc comment; `:145` `inclusion.logKeys: LogKeyEntry[] | LogKeyDoc` (2ac7b06). It is still a required field.
- `:515-517` exports `PINNED_LOG_KEYS`, `PINNED_LOG_KEYS_FETCHED_AT`, `LOG_KEYS_URL`; `:547` `checkLogKeyDoc`; `:555-557` types `LogKeyDoc`, `LogKeyDocEntry`, `LogKeyHandover` (2ef5ca6).
- `:480` is unchanged: `verifyReceipt` anchors a document on the bundle in use plus the pinned bundle (C2).

### Tests

- `test/cli.test.mjs` (6dc240c, e1924b3): +424 lines, 1 line edited (the import at the top, extended with `checkLogKeys` and `checkSthKey`). New tests at `:396-758`.
- `test/log.test.mjs` (2ef5ca6, 9ec8da9, 2ac7b06): +489 lines, 0 removed. New tests at `:687-1122`.

### Docs (7821233)

- `README.md`: options table row `:137`; exports list `:142`; library log section `:144-170`; "Log keys: the key document, today and after the cut-over" `:171-257` (fetch-else-pin snippet `:214-218`, fall back only on a 404 `:223`, the limits `:236-256`); "Array mode" `:258`; "Monitoring" `:287`; CLI section `:318-364` (usage `:324-328`, modes `:342-352`); migration bullet `:407`.
- `ARCHITECTURE.md`: `:13-14`, `:18-19` (file map), `:43-44` (step 8), `:65-85` (trusted for the log: array mode, document mode, today and after the cut-over).
- `CHANGELOG.md`: three "Added" bullets at `:16-18` and one "Fixed" bullet at `:36`, all under the existing `## 3.0.0 — unreleased (not published)` heading (`:3`). No new version heading (C5).

## 2. What was verified

**Suite.** `npm run build && npm test` on this tree: **195 tests, 195 pass, 0
fail**, exit 0. The baseline was re-measured in a clean checkout of 1b6edd2:
168 pass, 0 fail. The run adds 27 tests. Running only the new tests by name
(`node --test --test-name-pattern "key document|checkLogKeys|checkSthKey|PINNED_LOG_KEYS|checkLogKeyDoc|log-keys|receipt-key" test/cli.test.mjs test/log.test.mjs`)
gives 27 pass, 0 fail.

**Success criteria** (spec.md:55-60):

- **SC-001** — `npm run build && npm test` → 195 pass, 0 fail (195 > 168). Pass.
- **SC-002** — the named tests exist and pass in the run above; the list is below. Pass.
- **SC-003** — `grep -rn "tm-log-[0-9]" src/ scripts/` prints nothing (exit 1), and `git diff main -- test/ | grep -E "^\+" | grep -E "fetch\(|https?://"` prints nothing: no network call added. Pass, with the note below.
- **SC-004** — `node scripts/verify-log.mjs handover <PINNED_LOG_KEYS as JSON> --receipt-key=U18ONQCXr/Ox3Ac1ShKB1zYRcPIM9Sp9yZrka1jzoCY=` prints `{"valid":true,"reason":null}`, exit 0. Pass when run by hand; see the note below on "inside a test".
- **SC-005** — `git diff main -- test/ | grep "^-[^-]"` shows one removed line, the import in `test/cli.test.mjs`, which T001 names (it was extended). `test/log.test.mjs` has 0 removed lines. Every 3.0.0 test passes unedited. Pass.
- **SC-006** — `git diff --stat main` lists 12 files: `ARCHITECTURE.md`, `CHANGELOG.md`, `README.md`, `scripts/verify-log.mjs`, `src/index.ts`, `src/log.ts`, `src/pinned-keys.ts`, `test/cli.test.mjs`, `test/log.test.mjs`, and `plan.md`, `spec.md`, `tasks.md` in this spec directory (1789 insertions, 61 deletions). All are on the allowed list. `package.json` and `package-lock.json` are untouched, per C5; `package.json` still says 3.0.0. This file adds a thirteenth entry, also in the spec directory. Pass.

**SC-002, the tests by name.**

- Shared head under the real pin: `PINNED_LOG_KEYS: a valid key document anchored on the pinned receipt bundle` (`test/log.test.mjs:687`); `verifySth key document: a live-dialect shared head is valid under a one-entry document` (`:827`), which uses a generated key and asserts the document has the same entry fields as `PINNED_LOG_KEYS`; `verifySth key document: under the real PINNED_LOG_KEYS a tm-log-* head and a forged receipt-key head are refused` (`:846`). No test verifies a real head under the real pin: that needs the receipt private key or a network read, and tests have neither.
- Own-key head: `verifySth key document: an own-key head is valid above the cut-over and at it with the handed-over root` (`test/log.test.mjs:860`); `key document: valid shared head (one entry), shared head <= m and own-key head >= m (two entries)` (`test/cli.test.mjs:396`).
- Refusal reasons, CLI functions: `checkLogKeys: hand-over reasons` (`test/cli.test.mjs:442`: `handover_missing`, `handover_signature`, `handover_replay`, `handover_on_first_entry`); `checkLogKeys: bad_range (gap, zero width), bad_key_id, bad_entry (base64url key), bad_doc` (`:468`); `checkSthKey: the document is anchored on the pinned receipt key (first_key_not_pinned)` (`:494`); `checkSthKey: head reasons` (`:510`: `unknown_key_id`, `key_id_missing`, `key_id_mismatch`, `log_id_mismatch`, `tree_size_out_of_range`, `root_mismatch`).
- Refusal reasons, library: `checkLogKeyDoc: the first key must be a non-revoked receipt key; malformed input is a reason, never a throw` (`test/log.test.mjs:790`), plus the two agreement tests below.
- Library/CLI agreement (FR-008): `checkLogKeyDoc: same answer as the CLI checkLogKeys on every document vector` (`test/log.test.mjs:706`); `verifySth key document: the same reason as the CLI on every head vector (FR-008)` (`:881`).
- Across the cut-over: `CLI consistency --log-keys: a receipt-key head <= m to a log-key head > m passes` (`test/cli.test.mjs:683`) and its failing twin (`:705`); `CLI inclusion --log-keys: …` (`:717`); `verifySthConsistency key document: a proof spans the cut-over; a receipt-key head past it fails` (`test/log.test.mjs:1001`); `LogMonitor key document: shared heads, then the first own-key head advances with a consistency proof` (`:1018`); `verifyReceiptInclusion key document: …` (`:983`); `verifyReceipt key document: a receipt under a log-key head is included, log_key separate` (`:1061`).
- Constructor and guards: `LogMonitor key document: the constructor throws on a bad document or one for another log` (`:1037`); `key document callers: a signed head with no usable root_hash is refused, never thrown on` (`:1087`).

**SC-003, note.** The first grep prints nothing rather than "only the key-id
regex", because as a regular expression it needs a literal digit after
`tm-log-`, and the regex line itself has `[` there. The fixed-string search
`grep -rnF "tm-log-" src/ scripts/` prints four lines, the regex and its
comment in each file, and nothing else:

```
src/log.ts:228:// tm-log-YYYY-MM, the id every key after the first must carry.
src/log.ts:229:const LOG_KEY_ID_RE = /^tm-log-[0-9]{4}-(0[1-9]|1[0-2])$/;
scripts/verify-log.mjs:198:// tm-log-YYYY-MM. Same pattern as the sequencer's, repeated here so the
scripts/verify-log.mjs:200:const LOG_KEY_ID_RE = /^tm-log-[0-9]{4}-(0[1-9]|1[0-2])$/;
```

So no log key id and no log public key is committed in `src/` or `scripts/`.

**SC-004, note.** The spec says "run inside a test". No test spawns the CLI's
`handover` mode on the real pin. The test at `test/log.test.mjs:688-689`
asserts the same two checks as functions (`checkLogKeyDoc(PINNED_LOG_KEYS)`
and the CLI's `checkLogKeys(PINNED_LOG_KEYS)` both `null`), and the `handover`
mode itself is exercised on generated documents at `test/cli.test.mjs:593-601`.
The command line was run by hand for this closeout, with the result above.

**C1.** The bodies of `checkLogKeys` and `checkSthKey` here were compared, by
`diff`, with the same two functions in the Data API repo's
`scripts/verify-log.mjs` on its `main`: they differ in four comment lines and
nothing else. The helpers they call differ in the two places C1 allows:
`is32` and `sameKey` add `isB64`.

**C4.** The vector shaped exactly as the Data API emits it is
`key document: a Data-API-shaped document and heads are valid`
(`test/cli.test.mjs:413-439`): padded standard base64 keys and signatures,
`0x` + lower-case hex roots, `sth_timestamp` in the hand-over, the signer's
`key_id` and `public_key` in every signature. It asserts those spellings
(`:430-432`) and passes. The library's twin vector is `dataApi` (`:719`) in the
document-vector agreement test (`test/log.test.mjs:706`).

## 3. What was not verified, and known deltas

**No live own-key head exists.** The key ceremony has not happened, so the
log has never signed a head with its own key and no key document is served.
Every own-key vector in this run uses keys generated inside the tests. The
first real own-key head is checked by owner step (c) below.

**The Data API re-vendor is another run's work.** This file is the upstream
again (`scripts/verify-log.mjs:25-29`); copying it back into the Data API
repo was out of scope here.

**`isB64` delta for that re-vendor** (plan.md:87). The Data API copy's `is32`
and `sameKey` decode with a bare `Buffer.from(…, 'base64')`, which also takes
the base64url alphabet and skips junk. Here both call `isB64` first
(`scripts/verify-log.mjs:195`, `:197`). After the re-vendor the Data API's
own checks become stricter in the same way; its tests should expect that.

**C4: base64url spellings the Worker accepts are refused here.** The Worker's
decoder maps `-` and `_` to `+` and `/` and re-pads, so its `checkDoc` accepts
a key, a hand-over key or a signature spelled in base64url. This verifier
refuses a base64url key with `bad_entry`, in the library and in the CLI
(reproduced with a generated key; also `test/cli.test.mjs:468`). The Worker
emits standard padded base64, so a served document is not affected.

**C1: Worker `checkDoc` rules this verifier does not apply.** Compared rule
by rule: `checkDoc` in the Data API repo's `api/utils/log-signer.js` against
`checkLogKeys` here (`scripts/verify-log.mjs:207-238`; the library's
`checkLogKeyDocSync` applies the same set). A document with stray fields, a
non-Ed25519 `algorithm`, a non-boolean `shared_with_receipts`, a hand-over
without `sth_timestamp`, an upper-case root without `0x`, and a hand-over
signature naming another key was built with generated keys and accepted by
both the library and the CLI.

1. **`bad_json`.** The Worker takes the raw string and parses it. This verifier takes a parsed value; the CLI's own `JSON.parse` failure is an uncaught error, not a reason string.
2. **No unknown field in the document.** The Worker allows only `log_id` and `keys`. Not applied.
3. **No unknown field in an entry.** The Worker allows only `key_id`, `algorithm`, `public_key`, `from_tree_size`, `until_tree_size`, `shared_with_receipts`, `handover` (a stray `private_key` above all). Not applied.
4. **Entry `algorithm`, when present, must be `Ed25519`.** Not applied.
5. **Entry `shared_with_receipts`, when present, must be a boolean.** Not applied.
6. **The hand-over has exactly its nine fields** (`type`, `log_id`, `tree_size`, `root_hash`, `sth_timestamp`, `from_key_id`, `to_key_id`, `to_public_key`, `signature`). Not applied: extra fields are ignored and `sth_timestamp` is not required. When present it is covered by the signature like every other field.
7. **Hand-over `root_hash` is `0x` + 64 lower-case hex.** Here `0x` is optional and the case is free (`isHex32`, `:196`).
8. **The hand-over signature has exactly `algorithm`, `key_id`, `public_key`, `value`**, with a non-empty `key_id` and a 32-byte `public_key`. Here only `algorithm` and `value` are read.
9. **The hand-over signature names the previous key**: `signature.key_id` equals the previous entry's id and `signature.public_key` equals its key (the Worker's `handover_from_key`). Not applied. The signature must still verify under the previous entry's key, which is the rule that carries the trust.

Three Worker shape rules are applied here in effect, under a different reason
string: hand-over `tree_size` a size, `to_public_key` 32 bytes, and
`log_id` / `from_key_id` / `to_key_id` non-empty strings. Each is compared for
equality with an entry field that was already checked, so a bad value fails
as `handover_tree_size`, `handover_to_key`, `handover_log_id` or
`handover_from_key` instead of the Worker's `bad_handover`.

The anchor is outside `checkDoc` on both sides. The Worker's is in
`parseLogKeys` (reason `first_key_not_receipt_key`; it also accepts an exact
pinned id-and-key pair); here it is `first_key_not_pinned`, on key bytes
under any id.

None of rules 2–9 lets a head verify that should not: every key after the
first still needs a hand-over that verifies under the key before it, and the
first key must be the receipt key. They are publication hygiene on the
Worker's side (a pasted secret can never be served).

**The library is stricter than the CLI on signature padding.** Reproduced
with generated keys, padding stripped from an otherwise valid signature:

| Input | Library | CLI |
|---|---|---|
| hand-over signature without `=` padding | `checkLogKeyDoc` → `handover_signature` | `checkLogKeys` → `null` (accepted) |
| head signature without `=` padding | `verifySth` → `bad_signature` | `checkSthKey` → `null` (accepted) |

The library verifies through `ed25519Verify`, which takes canonical base64
only (`src/log.ts:177-188`, comment at `:374-375`); the CLI's `isB64`
(`scripts/verify-log.mjs:166`) allows zero to two `=`. The library is the
fail-closed side. Closing the gap means tightening the CLI. **No test vector
covers it**, so the agreement tests do not see it. The Worker emits padded
signatures.

**A revoked receipt key as anchor.** The library refuses it:
`checkLogKeyDoc(doc, [{ …receiptKey, status: 'revoked' }])` →
`first_key_not_pinned` (`src/log.ts:322`; reproduced; asserted by
`test/log.test.mjs:790`). The CLI's `--receipt-key` is a bare key with no
status, so it cannot know. A CLI user must not pass a revoked key.

**Open low findings from QA**, each re-checked on this tree:

- **Still holds:** a "document" whose `keys` is not an array slips past the `LogMonitor` constructor. `isKeyDoc` (`src/log.ts:337`) needs `keys` to be an array, so `{ log_id, keys: 'x' }` is not seen as a document, the check at `:733` is skipped and the constructor does not throw (reproduced). It fails closed afterwards: every `observe()` answers `invalid` with "no pinned log key". `keys: []` does throw (`bad_doc`).
- **Still holds, one place found:** the doc comment written for `verifySthDoc` (`src/log.ts:331-334`) sits above `isKeyDoc` (`:337`), so tooling attaches it to the wrong function; `verifySthDoc` at `:339` has none. The T004 and T005 reports each mention one misplaced comment. Only this one could be found in `src/log.ts` now; the two reports may describe the same lines.
- **Still holds:** no CLI test asserts `duplicate_key_id` (0 matches in `test/cli.test.mjs`). The library's document-vector test covers it and compares with the CLI function.
- **Still holds:** the header sentence at `scripts/verify-log.mjs:60` says "Missing --key … exits 2" without naming the `--log-keys` alternative; `:69-70` says it correctly.

**`verifyReceipt`'s `inclusion.logKeys` stays required** (spec.md:79;
`src/index.ts:145`). It does not default to `PINNED_LOG_KEYS`: a default
would turn today's "no pinned log key" error into a pass for callers who
omitted it. GATE 0 did not flip this.

**Not run here:** CI (Node 20/22/24) runs on the draft PR; this closeout ran
the suite on one local Node version only. No production read or write was
made in this task.

## 4. Built against

The runbook and hand-over version of draft tunnelmind-data-api#123, the
stricter one (its runbook pre-check looks the key up by the head's own
`signature.key_id`); its `scripts/verify-log.mjs` equals Data API `main`.
This is as recorded in tasks.md T007 and spec.md:15, not re-checked in this
task: the draft PR could not be read offline. What was checked offline is the
`main` side: the two ported functions equal the Data API `main` copy apart
from comments (section 2, C1).

Sources: the Data API's ADR-047 §4 (key document), §5 (signed `key_id`), §6
(hand-over record), §7 (verifier rule), §8 (heads before the cut-over), and
`docs/LOG-KEY-RUNBOOK.md`.

## 5. Owner steps, in order

**(a) Give the merge word on the draft PR.** The coordinator opens the draft
PR after GATE F; nothing is merged without the owner's word.
Check-after: the PR is merged and CI is green.

**(b) Publish 3.0.0, BEFORE runbook step 5.** Push the tag `v3.0.0`;
`.github/workflows/publish.yml` publishes on a `v*` tag.

Correction to the text of T007 and T008 in tasks.md: they say "publish 3.1.0"
and a check-after that prints 3.1.0. Per GATE 0 condition C5 the version is
**3.0.0**. npm has only 1.0.0 and 2.0.0; 3.0.0 was never published, so this
run's entries sit under the existing "3.0.0 — unreleased" heading in
`CHANGELOG.md` and `package.json` was not bumped. tasks.md is left as written;
this paragraph is the record of the correction.

Check-after: `npm view @tunnelmindai/receipt-verify version` prints 3.0.0.

**(c) After the ceremony (runbook step 4 done), optionally refresh the pin in
one PR.** Nothing is required for correctness: a caller that passes the
served document gets own-key heads verified the moment it is published.
Recommended: replace the `PINNED_LOG_KEYS` literal in `src/pinned-keys.ts`
with the served document, verbatim, set `PINNED_LOG_KEYS_FETCHED_AT`, and
release. Until then the shipped pin refuses log-key heads (`unknown_key_id`)
and still accepts receipt-key heads above the hand-over size.

Check-after, from plan.md (4): `npm test` green, and
`node scripts/verify-log.mjs handover <pinned-copy.json> --receipt-key=<receipt-pub>`
prints `{"valid":true,"reason":null}`, and
`node scripts/verify-log.mjs sth sth.json --log-keys <pinned-copy.json> --receipt-key=<receipt-pub>`
on the live head prints `valid: true` with `key_id` `<id>`.
- Version is 3.0.0 and unreleased.
