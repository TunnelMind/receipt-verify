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

test('the head reports its own signed date as sth_timestamp', async () => {
  const { receipt, data } = await logged();
  const r = await verifyReceipt(receipt, { ...base(), fetcher: serve(() => json({ ok: true, data })).fetcher });
  assert.equal(r.log.sth_timestamp, data.sth.timestamp);
  // A head with no timestamp still proves inclusion; it just has no date.
  const { signature: _s, timestamp: _t, ...body } = data.sth;
  const bare = await signSth(issuer, body);
  const r2 = await verifyReceipt(receipt, { ...base(), fetcher: serve(() => json({ ok: true, data: { ...data, sth: bare } })).fetcher });
  assert.equal(r2.log.status, 'included', r2.errors.join('; '));
  assert.equal(r2.log.sth_timestamp, undefined);
});

// After a log-key change: the served document hands the log over from the
// receipt key to a new log key at tree size 5, and heads past it are signed
// by the new key. Hand-over as log.test.mjs kdHandover builds it.
const NEW_KID = 'tm-log-2026-12';
async function handedOver(from, to, over = {}) {
  const body = {
    type: 'tunnelmind.log-key-handover/v1', log_id: PINNED_LOG_KEYS.log_id,
    from_key_id: KEY_ID, to_key_id: NEW_KID, to_public_key: to.publicKeyB64,
    tree_size: 5, root_hash: hex(Buffer.alloc(32, 0x55)), ...over,
  };
  const sig = await subtle.sign('Ed25519', from.kp.privateKey, canonicalizeBytes(body));
  return {
    log_id: body.log_id,
    keys: [
      { key_id: KEY_ID, public_key: issuer.publicKeyB64, from_tree_size: 0, until_tree_size: 5 },
      { key_id: NEW_KID, public_key: to.publicKeyB64, from_tree_size: 5, until_tree_size: null,
        handover: { ...body, signature: { algorithm: 'Ed25519', value: Buffer.from(sig).toString('base64') } } },
    ],
  };
}

test('logKeys: after a log-key change the served document lets new heads verify', async () => {
  const logKey = await makeEphemeralKey();
  const { receipt, data } = await logged();
  const { signature: _s, ...body } = data.sth;
  const sig = await subtle.sign('Ed25519', logKey.kp.privateKey, canonicalizeBytes({ ...body, key_id: NEW_KID }));
  const sth = { ...body, key_id: NEW_KID, signature: { algorithm: 'Ed25519', key_id: NEW_KID, value: Buffer.from(sig).toString('base64') } };
  const { fetcher } = serve(() => json({ ok: true, data: { ...data, sth } }));
  // The pins alone do not know the new key: every receipt fails.
  const pinned = await verifyReceipt(receipt, { ...base(), fetcher });
  assert.equal(pinned.log.status, 'failed');
  assert.match(pinned.errors.join(';'), /unknown_key_id/);
  // The served document, chained from the pinned receipt key: included.
  const served = await handedOver(issuer, logKey);
  const r = await verifyReceipt(receipt, { ...base(), fetcher, logKeys: served });
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.equal(r.log.log_key_id, NEW_KID);
  assert.equal(r.log.log_key, 'separate');
  // Not chained to the pins, or for another log: refused.
  const attacker = await makeEphemeralKey();
  const cases = [
    [await handedOver(attacker, logKey), 'hand-over signed by an unpinned key'],
    [{ ...served, keys: [{ ...served.keys[0], public_key: attacker.publicKeyB64 }, served.keys[1]] }, 'first key not a pinned receipt key'],
    [await handedOver(issuer, logKey, { log_id: 'other-log' }).then((d) => ({ ...d, log_id: 'other-log' })), 'document for another log'],
  ];
  for (const [doc, why] of cases) {
    const x = await verifyReceipt(receipt, { ...base(), fetcher, logKeys: doc });
    assert.equal(x.valid, false, why);
    assert.equal(x.log.status, 'failed', why);
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

// ── Fable round 3 ────────────────────────────────────────────────────────────

test('logKeys must be a key document: a bare key array would skip the pin anchor (R3-1)', async () => {
  const attacker = await makeEphemeralKey();
  const forged = await logged(attacker); // a receipt in no log, head signed by a fresh key
  const { urls, fetcher } = serve(() => json({ ok: true, data: forged.data }));
  for (const logKeys of [
    [{ key_id: 'evil-key', public_key: attacker.publicKeyB64 }],
    [{ key_id: KEY_ID, public_key: attacker.publicKeyB64 }],
    'tm-log', 42, null, { log_id: PINNED_LOG_KEYS.log_id },
  ]) {
    const r = await verifyReceipt(forged.receipt, { ...base(), fetcher, logKeys });
    assert.equal(r.valid, false, JSON.stringify(logKeys));
    assert.notEqual(r.log.status, 'included', JSON.stringify(logKeys));
    assert.match(r.errors.join(';'), /logKeys must be a key document/, JSON.stringify(logKeys));
  }
  assert.equal(urls.length, 0); // refused before the receipt_id is sent
});

test('a document for another log, anchored on the pinned key, is refused (logId stays bound)', async () => {
  const { receipt } = await logged();
  const D = Array.from({ length: 7 }, (_, i) => refLeaf(Buffer.from(`leaf-${i}`)));
  D[4] = Buffer.from(await receiptLeafHash(receipt));
  const sth = await signSth(issuer, { log_id: 'other-log', tree_size: 7, root_hash: hex(MTH(D)), timestamp: new Date().toISOString() });
  const data = { leaf_index: 4, tree_size: 7, leaf_hash: hex(D[4]), audit_path: PATH(4, D).map(hex), root_hash: hex(MTH(D)), sth };
  const logKeys = { log_id: 'other-log', keys: [{ key_id: KEY_ID, public_key: issuer.publicKeyB64, from_tree_size: 0, until_tree_size: null }] };
  const r = await verifyReceipt(receipt, { ...base(), fetcher: serve(() => json({ ok: true, data })).fetcher, logKeys });
  assert.equal(r.valid, false);
  assert.equal(r.log.status, 'failed');
  assert.match(r.errors.join(';'), /log_id_mismatch/);
});

test('the proof fetch refuses redirects (R3-2)', async () => {
  const { receipt, data } = await logged();
  const inits = [];
  const fetcher = async (_u, init) => { inits.push(init); return json({ ok: true, data }); };
  const r = await verifyReceipt(receipt, { ...base(), fetcher });
  assert.equal(r.log.status, 'included', r.errors.join('; '));
  // 'manual', not 'error': Workers throw on 'error' (R4-1).
  assert.equal(inits[0]?.redirect, 'manual');
  // A fetcher that hands back a 3xx anyway: not a proof.
  const moved = serve(() => new Response('', { status: 302, headers: { location: 'http://elsewhere.example/' } }));
  const r2 = await verifyReceipt(receipt, { ...base(), fetcher: moved.fetcher });
  assert.equal(r2.log.status, 'not_checked');
  assert.match(r2.errors.join(';'), /returned 302/);
});

test('error texts label a failure only whole, and only on their own status (R3-3)', async () => {
  const { receipt } = await logged();
  const id = receipt.receipt_id;
  const err = (status, error) => () => json({ ok: false, error, code: status }, status);
  const cases = [
    [err(404, `x receipt ${id} is not yet sequenced into the log`), 'pending text with a prefix'],
    [err(404, `receipt ${id} is not yet sequenced into the log x`), 'pending text with a suffix'],
    [err(404, `x no receipt ${id}`), 'absent text with a prefix'],
    [err(404, `no receipt ${id} x`), 'absent text with a suffix'],
    [err(400, 'x leaf_index 9 is outside tree_size 7'), 'past-head text with a prefix'],
    [err(400, 'leaf_index 9 is outside tree_size 7 x'), 'past-head text with a suffix'],
    [err(500, `receipt ${id} is not yet sequenced into the log`), 'pending text on a 500'],
    [err(503, `no receipt ${id}`), 'absent text on a 503'],
    [err(404, 'leaf_index 9 is outside tree_size 7'), 'past-head text on a 404'],
    [err(400, `no receipt ${id}`), 'absent text on a 400'],
    [err(400, `receipt ${id} is not yet sequenced into the log`), 'pending text on a 400'],
  ];
  for (const [respond, why] of cases) {
    const r = await verifyReceipt(receipt, { ...base(), fetcher: serve(respond).fetcher });
    assert.equal(r.valid, false, why);
    assert.equal(r.log.status, 'not_checked', why);
  }
});

test('only requireInclusion: false opts out; other falsy values still require inclusion (R3-3)', async () => {
  const { receipt } = await logged();
  for (const v of [0, null, '', undefined, 'false']) {
    const { urls, fetcher } = serve(noReceipt(receipt.receipt_id));
    const r = await verifyReceipt(receipt, { ...base(), fetcher, requireInclusion: v });
    assert.equal(r.valid, false, String(v));
    assert.equal(r.log.status, 'absent', String(v));
    assert.equal(urls.length, 1, String(v));
  }
});

test('sth_timestamp is reported only for a proof that verified (R3-3)', async () => {
  const { receipt, data } = await logged();
  const r = await verifyReceipt(receipt, { ...base(), fetcher: serve(() => json({ ok: true, data: { ...data, leaf_index: 3 } })).fetcher });
  assert.equal(r.log.status, 'failed');
  assert.equal(r.log.sth_timestamp, undefined);
});
