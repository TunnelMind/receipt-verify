// verifyReceipt step 8 default path (4.0.0): with no `inclusion` and the
// pinned bundle in use, the proof is fetched by receipt_id and checked under
// PINNED_LOG_KEYS. The real pinned keys have no private half here, and the
// exported PINNED_* objects are frozen, so this file points the internal
// dist/active-pins.js (not reachable through the package's exports) at a
// test bundle and log-key document, in this process only (node --test runs
// each file in its own process), and serves the log through an injected
// fetcher. Proofs come from the same
// recursive RFC 6962 reference as log.test.mjs.

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { canonicalizeBytes } from '../dist/jcs.js';
import {
  verifyReceipt,
  verifyReceiptJson,
  receiptLeafHash,
  DEFAULT_LOG_PROOF_URL,
  PINNED_KEY_BUNDLE,
  PINNED_LOG_KEYS,
} from '../dist/index.js';
import { ACTIVE_PINS } from '../dist/active-pins.js';
import { makeReceipt, makeEphemeralKey, makeRevocations } from './_helpers.mjs';

const subtle = webcrypto.subtle;
const KEY_ID = 'tm-receipt-2026-05';

const H = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const refLeaf = (data) => H(Buffer.from([0]), data);
const refNode = (l, r) => H(Buffer.from([1]), l, r);
const splitK = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
function MTH(D) {
  if (D.length === 1) return D[0];
  const k = splitK(D.length);
  return refNode(MTH(D.slice(0, k)), MTH(D.slice(k)));
}
function PATH(m, D) {
  if (D.length <= 1) return [];
  const k = splitK(D.length);
  return m < k ? [...PATH(m, D.slice(0, k)), MTH(D.slice(k))]
               : [...PATH(m - k, D.slice(k)), MTH(D.slice(0, k))];
}
const hex = (b) => '0x' + Buffer.from(b).toString('hex');

let issuer;
before(async () => {
  issuer = await makeEphemeralKey();
  ACTIVE_PINS.bundle = {
    ...PINNED_KEY_BUNDLE,
    keys: [{
      key_id: KEY_ID, algorithm: 'Ed25519', public_key: issuer.publicKeyB64, status: 'active',
      created_at: '2026-01-01T00:00:00Z', rotation_after: '2099-01-01T00:00:00Z', attestation_strength: 'software',
    }],
  };
  ACTIVE_PINS.logKeys = {
    log_id: PINNED_LOG_KEYS.log_id,
    keys: [{ key_id: KEY_ID, public_key: issuer.publicKeyB64, from_tree_size: 0, until_tree_size: null, shared_with_receipts: true }],
  };
});

async function signSth(signer, body) {
  const sig = await subtle.sign('Ed25519', signer.kp.privateKey, canonicalizeBytes(body));
  return { ...body, signature: { algorithm: 'Ed25519', key_id: KEY_ID, value: Buffer.from(sig).toString('base64') } };
}

/** A receipt by the pinned key at index 4 of a 7-leaf log, and the
 *  /v1/receipts/log/proof `data` for it (proof + latest STH). */
async function logged(signer = issuer) {
  const { receipt } = await makeReceipt({ keyId: KEY_ID, kp: issuer.kp, publicKeyB64: issuer.publicKeyB64 });
  const D = Array.from({ length: 7 }, (_, i) => refLeaf(Buffer.from(`leaf-${i}`)));
  D[4] = Buffer.from(await receiptLeafHash(receipt));
  const root = MTH(D);
  const sth = await signSth(signer, { log_id: PINNED_LOG_KEYS.log_id, tree_size: 7, root_hash: hex(root), timestamp: new Date().toISOString() });
  const data = { leaf_index: 4, tree_size: 7, leaf_hash: hex(D[4]), audit_path: PATH(4, D).map(hex), root_hash: hex(root), sth };
  return { receipt, data };
}

/** A fetcher that records every URL and answers with `respond(url)`. */
function serve(respond) {
  const urls = [];
  const fetcher = async (url) => { urls.push(url); return respond(url); };
  return { urls, fetcher };
}
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const base = () => ({ revocations: makeRevocations() });

test('default: the proof is fetched by receipt_id and the receipt is included', async () => {
  const { receipt, data } = await logged();
  const { urls, fetcher } = serve(() => json({ ok: true, data }));
  const r = await verifyReceipt(receipt, { ...base(), fetcher });
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.deepEqual(r.log, { status: 'included', tree_size: 7, leaf_index: 4, log_key_id: KEY_ID, log_key: 'shared_with_receipts', sth_timestamp: data.sth.timestamp });
  assert.deepEqual(urls, [`${DEFAULT_LOG_PROOF_URL}?receipt_id=${receipt.receipt_id}`]);
  // Same through the text entry point.
  const t = await verifyReceiptJson(JSON.stringify(receipt), { ...base(), fetcher });
  assert.equal(t.log.status, 'included', t.errors.join('; '));
});

test('default: a fetched proof is trusted no more than a supplied one', async () => {
  const { receipt, data } = await logged();
  const attacker = await makeEphemeralKey();
  const forged = await logged(attacker); // head signed by an unpinned key
  const { receipt: other } = await makeReceipt({ keyId: KEY_ID, kp: issuer.kp, publicKeyB64: issuer.publicKeyB64, payload: { other: true } });
  const cases = [
    [{ ...forged.data }, 'head signed by an unpinned key', forged.receipt],
    [{ ...data, leaf_hash: hex(await receiptLeafHash(other)) }, 'lying leaf_hash is ignored', other],
    [{ ...data, root_hash: hex(Buffer.alloc(32, 0xcd)) }, 'proof root disagrees with the head', receipt],
    [{ ...data, leaf_index: 3 }, 'wrong index', receipt],
    [{ ...data, sth: { ...data.sth, log_id: 'other-log' } }, 'head for another log', receipt],
  ];
  for (const [body, why, rcpt] of cases) {
    const { fetcher } = serve(() => json({ ok: true, data: body }));
    const r = await verifyReceipt(rcpt, { ...base(), fetcher });
    assert.equal(r.valid, false, why);
    assert.equal(r.log.status, 'failed', why);
    assert.ok(r.errors.some((e) => e.startsWith('log inclusion:')), why);
  }
});

test('default: no proof available is an error, never a pass', async () => {
  const { receipt } = await logged();
  const cases = [
    [() => json({ ok: false, error: 'no signed tree head published yet', code: 404 }, 404), /proof fetch failed: .* returned 404/, 'no head'],
    [() => new Response('', { status: 404 }), /returned 404/, 'bare 404'],
    [() => json({ ok: false }, 503), /returned 503/, '503'],
    [() => json({ data: {} }), /not \{ ok: true, data \}/, 'no envelope'],
    [() => new Response('<html>', { status: 200 }), /proof fetch failed/, 'not JSON'],
    [() => { throw new Error('offline'); }, /offline/, 'network'],
  ];
  for (const [respond, want, why] of cases) {
    const { fetcher } = serve(respond);
    const r = await verifyReceipt(receipt, { ...base(), fetcher });
    assert.equal(r.valid, false, why);
    assert.equal(r.log.status, 'not_checked', why);
    assert.match(r.errors.join(';'), want, why);
  }
});

// The endpoint's own 404 texts (data-api receipt-log.js getInclusionProof).
const notSequenced = (id) => () => json({ ok: false, error: `receipt ${id} is not yet sequenced into the log`, code: 404 }, 404);
const noReceipt = (id) => () => json({ ok: false, error: `no receipt ${id}`, code: 404 }, 404);

test('pending: logged but not in a signed head yet reads pending, never valid', async () => {
  const { receipt } = await logged();
  const { fetcher } = serve(notSequenced(receipt.receipt_id));
  const r = await verifyReceipt(receipt, { ...base(), fetcher });
  assert.equal(r.valid, false);
  assert.equal(r.log.status, 'pending');
  assert.match(r.errors.join(';'), /^log inclusion: pending: .*verify again after the next head$/m);
  // Every other check still ran and passed: pending is the only error.
  assert.equal(r.errors.length, 1, r.errors.join('; '));
});

test('absent: the log has no record of the receipt', async () => {
  const { receipt } = await logged();
  const { fetcher } = serve(noReceipt(receipt.receipt_id));
  const r = await verifyReceipt(receipt, { ...base(), fetcher });
  assert.equal(r.valid, false);
  assert.equal(r.log.status, 'absent');
  assert.match(r.errors.join(';'), /the log has no record of receipt/);
});

test('includedBy: a commit before market close must sit in a head signed before close', async () => {
  const { receipt, data } = await logged();
  const headMs = Date.parse(data.sth.timestamp);
  const at = (ms) => new Date(ms).toISOString();
  const ok = serve(() => json({ ok: true, data }));
  // Head signed before the deadline: included.
  const r1 = await verifyReceipt(receipt, { ...base(), fetcher: ok.fetcher, includedBy: at(headMs + 60_000) });
  assert.equal(r1.valid, true, r1.errors.join('; '));
  assert.equal(r1.log.status, 'included');
  assert.equal(r1.log.sth_timestamp, data.sth.timestamp);
  // The only proof is against a head signed after close: fails, though the
  // receipt is in the log (it may have been sequenced only after the outcome).
  const r2 = await verifyReceipt(receipt, { ...base(), fetcher: ok.fetcher, includedBy: at(headMs - 60_000) });
  assert.equal(r2.valid, false);
  assert.equal(r2.log.status, 'failed');
  assert.match(r2.errors.join(';'), /after includedBy/);
  // A supplied proof is held to the same deadline.
  const r3 = await verifyReceipt(receipt, { ...base(), inclusion: { proof: data, logKeys: ACTIVE_PINS.logKeys }, includedBy: at(headMs - 1) });
  assert.equal(r3.log.status, 'failed');
  assert.match(r3.errors.join(';'), /after includedBy/);
  // The boundary: a head signed at the deadline itself meets it.
  const r3b = await verifyReceipt(receipt, { ...base(), fetcher: ok.fetcher, includedBy: data.sth.timestamp });
  assert.equal(r3b.log.status, 'included', r3b.errors.join('; '));
  // Committed in the last hour, close not reached yet: pending.
  const q = serve(notSequenced(receipt.receipt_id));
  const r4 = await verifyReceipt(receipt, { ...base(), fetcher: q.fetcher, includedBy: at(Date.now() + 3_600_000) });
  assert.equal(r4.log.status, 'pending');
  // Close has passed and it is still unsequenced: it can no longer be logged
  // in time, so it fails rather than waits.
  const r5 = await verifyReceipt(receipt, { ...base(), fetcher: q.fetcher, includedBy: at(Date.now() - 1000) });
  assert.equal(r5.valid, false);
  assert.equal(r5.log.status, 'failed');
  assert.match(r5.errors.join(';'), /not in a tree head signed by includedBy/);
  // A head with no timestamp cannot meet a deadline; a bad deadline is an error.
  const { signature: _s, timestamp: _t, ...body } = data.sth;
  const bare = await signSth(issuer, body);
  const noDeadline = await verifyReceipt(receipt, { ...base(), fetcher: serve(() => json({ ok: true, data: { ...data, sth: bare } })).fetcher });
  assert.equal(noDeadline.log.status, 'included', noDeadline.errors.join('; '));
  const r6 = await verifyReceipt(receipt, { ...base(), fetcher: serve(() => json({ ok: true, data: { ...data, sth: bare } })).fetcher, includedBy: at(headMs + 60_000) });
  assert.equal(r6.valid, false);
  assert.match(r6.errors.join(';'), /needs a tree head with an RFC 3339 timestamp/);
});

test('includedBy and head dates must be RFC 3339 with a zone; a bad value never throws', async () => {
  const { receipt, data } = await logged();
  const ok = serve(() => json({ ok: true, data }));
  // Date.parse takes all of these; none is a dated instant every verifier
  // reads the same way (a zone-less time is the verifier's local time).
  for (const bad of ['before close', '2027', 2027, new Date(), '2026-11-21T12:00:00', 'Nov 21 2026 13:00', Symbol('x'), null]) {
    const r = await verifyReceipt(receipt, { ...base(), fetcher: ok.fetcher, includedBy: bad });
    assert.equal(r.valid, false, String(typeof bad));
    assert.match(r.errors.join(';'), /includedBy: not an RFC 3339 date-time with a zone/, String(typeof bad));
  }
  // A signed head whose timestamp is not RFC 3339 cannot meet a deadline.
  for (const ts of ['2026', 'Sat Nov 21 2026', '2026-11-21T12:00:00']) {
    const sth = await signSth(issuer, { ...(({ signature, ...b }) => b)(data.sth), timestamp: ts });
    const r = await verifyReceipt(receipt, { ...base(), fetcher: serve(() => json({ ok: true, data: { ...data, sth } })).fetcher, includedBy: '2099-01-01T00:00:00Z' });
    assert.equal(r.log.status, 'failed', ts);
    assert.match(r.errors.join(';'), /needs a tree head with an RFC 3339 timestamp/, ts);
  }
});

test('pending also covers a receipt sequenced past the latest signed head (400)', async () => {
  const { receipt } = await logged();
  const past = serve(() => json({ ok: false, error: 'leaf_index 9 is outside tree_size 7', code: 400 }, 400));
  const r = await verifyReceipt(receipt, { ...base(), fetcher: past.fetcher });
  assert.equal(r.valid, false);
  assert.equal(r.log.status, 'pending');
  // Any other 400 is not a label: fetch failed.
  const other = serve(() => json({ ok: false, error: 'malformed receipt_id', code: 400 }, 400));
  const r2 = await verifyReceipt(receipt, { ...base(), fetcher: other.fetcher });
  assert.equal(r2.log.status, 'not_checked');
  // The 404 texts are matched whole: one that mixes both reads as neither.
  const mixed = serve(() => json({ ok: false, error: 'no receipt x is not yet sequenced into the log', code: 404 }, 404));
  const r3 = await verifyReceipt(receipt, { ...base(), fetcher: mixed.fetcher });
  assert.equal(r3.log.status, 'not_checked');
});

test('a receipt that already failed is not sent to the log', async () => {
  const { receipt } = await logged();
  const bad = { ...receipt, signature: { ...receipt.signature, value: Buffer.alloc(64).toString('base64') } };
  const { urls, fetcher } = serve(() => { throw new Error('must not fetch'); });
  const r = await verifyReceipt(bad, { ...base(), fetcher });
  assert.equal(r.valid, false);
  assert.equal(r.log.status, 'not_checked');
  assert.match(r.errors.join(';'), /log inclusion: not checked: the receipt already failed/);
  assert.equal(urls.length, 0);
});

test('requireInclusion: false skips the log without fetching', async () => {
  const { receipt } = await logged();
  const { urls, fetcher } = serve(() => { throw new Error('must not fetch'); });
  const r = await verifyReceipt(receipt, { ...base(), fetcher, requireInclusion: false });
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.equal(r.log.status, 'not_checked');
  assert.equal(urls.length, 0);
});

test('logProofUrl overrides the endpoint; a non-log receipt_id is never sent', async () => {
  const { receipt, data } = await logged();
  const { urls, fetcher } = serve(() => json({ ok: true, data }));
  const r = await verifyReceipt(receipt, { ...base(), fetcher, logProofUrl: 'https://mirror.example/proof' });
  assert.equal(r.log.status, 'included', r.errors.join('; '));
  assert.deepEqual(urls, [`https://mirror.example/proof?receipt_id=${receipt.receipt_id}`]);

  const { receipt: odd } = await makeReceipt({
    keyId: KEY_ID, kp: issuer.kp, publicKeyB64: issuer.publicKeyB64,
    mutate: (x) => { x.receipt_id = 'a&tree_size=1'; },
  });
  const spy = serve(() => json({ ok: true, data }));
  const r2 = await verifyReceipt(odd, { ...base(), fetcher: spy.fetcher });
  assert.equal(r2.valid, false);
  assert.match(r2.errors.join(';'), /receipt_id is not a log id/);
  assert.equal(spy.urls.length, 0);
});
