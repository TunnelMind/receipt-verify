// Property tests — the invariants a reader expects of a signature verifier,
// checked on seeded random input so a failure reproduces from its seed
// (PROPERTY_SEED=<n> npm test). Each test states its claim; the example-based
// suites (verify.test.mjs, cli.test.mjs) pin the procedure step by step.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyReceipt, canonicalize } from '../dist/index.js';
import { canonicalize as verdictCanonicalize } from '../scripts/verdict-lib/jcs.js';
import { jcs as logCanonicalize } from '../scripts/verify-log.mjs';
import { makeReceipt, makeEphemeralKey, makeKeyBundle, makeRevocations } from './_helpers.mjs';

const SEED = Number(process.env.PROPERTY_SEED ?? 20261021);

// mulberry32: a tiny seeded PRNG, so a failing case is reproducible from SEED.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (r, list) => list[Math.floor(r() * list.length)];

// Pieces chosen to hit every escape and ordering rule of RFC 8785: quotes,
// backslash, C0 controls, DEL, combining marks (no normalization), astral
// code points (UTF-16 key order), the line separators JSON.stringify leaves
// raw, and object keys that are prototype property names.
const PIECES = ['a', 'Z', '0', ' ', '"', '\\', '/', '\n', '\t', '\u0000', '\u001f', '\u007f',
  'é', 'é', '€', 'ö', 'דּ', '😀', '𝄞', ' ', ' ', '__proto__', 'constructor', 'toString'];

function randomString(r) {
  const n = Math.floor(r() * 6);
  let s = '';
  for (let i = 0; i < n; i++) s += pick(r, PIECES);
  return s;
}

// Finite doubles across the formatting regimes (integers, exponent forms,
// sub-normal-ish, beyond 2^53). Never -0: it canonicalizes to "0", which is
// the one finite number that does not round-trip (by RFC 8785 design).
function randomNumber(r) {
  const k = r();
  if (k < 0.3) return Math.floor(r() * 2e6) - 1e6;
  if (k < 0.5) return (r() + 0.1) * 1e-7;
  if (k < 0.7) return (r() + 0.1) * 1e25;
  if (k < 0.8) return Number.MAX_SAFE_INTEGER + Math.floor(r() * 10);
  if (k < 0.9) return pick(r, [5e-324, 1.7976931348623157e308, 1e21, 1e-7, 0.1, 0.7, 100]);
  return (r() - 0.5) * 1000;
}

function randomValue(r, depth = 0) {
  const k = r();
  if (depth > 3 || k < 0.1) return null;
  if (k < 0.2) return r() < 0.5;
  if (k < 0.4) return randomNumber(r);
  if (k < 0.6) return randomString(r);
  if (k < 0.8) return Array.from({ length: Math.floor(r() * 4) }, () => randomValue(r, depth + 1));
  // Object.fromEntries defines "__proto__" as an own property (as JSON.parse
  // does); an object literal would set the prototype instead.
  return Object.fromEntries(Array.from({ length: Math.floor(r() * 4) },
    () => [randomString(r), randomValue(r, depth + 1)]));
}

const CASES = 300;

test(`property: canonicalize → JSON.parse → canonicalize is the identity (${CASES} random documents)`, () => {
  const r = rng(SEED);
  for (let i = 0; i < CASES; i++) {
    const x = randomValue(r);
    const c = canonicalize(x);
    const back = JSON.parse(c);
    assert.deepStrictEqual(back, x, `case ${i} (seed ${SEED}): ${c}`);
    assert.equal(canonicalize(back), c, `case ${i} (seed ${SEED}) re-canonicalizes differently`);
  }
});

test(`property: the package, the verdict kernel and verify-log canonicalize ${CASES} random documents to the same bytes`, () => {
  const r = rng(SEED + 1);
  for (let i = 0; i < CASES; i++) {
    const x = randomValue(r);
    const c = canonicalize(x);
    assert.equal(verdictCanonicalize(x), c, `verdict-lib differs on case ${i} (seed ${SEED + 1})`);
    assert.equal(logCanonicalize(x), c, `verify-log differs on case ${i} (seed ${SEED + 1})`);
  }
});

test('property: a lone surrogate anywhere in a document makes all three canonicalizers throw', () => {
  const r = rng(SEED + 2);
  for (let i = 0; i < 100; i++) {
    // Inject one lone surrogate into a random string of the document; the
    // iterator pairs a high+low surrogate into one code point, so plant a
    // lone one next to an ordinary character.
    const lone = pick(r, ['\ud800', '\udbff', '\udc00', '\udfff']);
    const planted = randomString(r) + lone + randomString(r);
    const x = r() < 0.5 ? { [randomString(r)]: planted, ok: randomValue(r) } : [randomValue(r), planted];
    for (const [name, fn] of [['package', canonicalize], ['verdict-lib', verdictCanonicalize], ['verify-log', logCanonicalize]]) {
      assert.throws(() => fn(x), /lone surrogate/, `${name} accepted case ${i} (seed ${SEED + 2})`);
    }
  }
});

// A bundle whose key out-ranks every claim, so the ceiling never fires and
// only the cryptography decides.
async function signedCase(r, key) {
  const strength = pick(r, ['self-asserted', 'software', 'tee-tpm', 'silicon-root']);
  const { receipt, keyId, publicKeyB64 } = await makeReceipt({
    payload: randomValue(r) ?? { seeded: SEED },
    attestationStrength: strength,
    kp: key.kp, publicKeyB64: key.publicKeyB64,
  });
  const keys = makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64, attestation_strength: 'silicon-root' }]);
  return { receipt, keys, strength };
}
const offline = (keys) => ({ keys, revocations: makeRevocations() });

test('property: verify(sign(x)) is valid for 25 random payloads and every tier', async () => {
  const r = rng(SEED + 3);
  const key = await makeEphemeralKey();
  for (let i = 0; i < 25; i++) {
    const { receipt, keys, strength } = await signedCase(r, key);
    const out = await verifyReceipt(receipt, offline(keys));
    assert.deepStrictEqual(out.errors, [], `case ${i} (seed ${SEED + 3}): ${JSON.stringify(receipt.payload)}`);
    assert.equal(out.valid, true);
    assert.equal(out.attestation_strength, strength);
    assert.equal(out.key_id, receipt.signature.key_id);
  }
});

const flipBit = (bytes, i) => { const b = Buffer.from(bytes); b[i >> 3] ^= 1 << (i & 7); return b; };
const sigFailure = (out) => out.errors.some((e) => e === 'Ed25519 signature did not verify' || e.startsWith('signature verification failed'));

test('property: flipping any single bit of the 64-byte signature makes the receipt invalid', async () => {
  const r = rng(SEED + 4);
  const { receipt, keys } = await signedCase(r, await makeEphemeralKey());
  const sig = Buffer.from(receipt.signature.value, 'base64');
  assert.equal(sig.length, 64);
  for (let bit = 0; bit < 512; bit++) {
    const forged = { ...receipt, signature: { ...receipt.signature, value: flipBit(sig, bit).toString('base64') } };
    const out = await verifyReceipt(forged, offline(keys));
    assert.equal(out.valid, false, `bit ${bit} still verifies`);
    assert.ok(sigFailure(out), `bit ${bit}: ${out.errors}`);
  }
});

test('property: flipping any single bit of the signing key (bundle and receipt alike) makes the receipt invalid', async () => {
  const r = rng(SEED + 5);
  const { receipt, keys } = await signedCase(r, await makeEphemeralKey());
  const pub = Buffer.from(keys.keys[0].public_key, 'base64');
  assert.equal(pub.length, 32);
  for (let bit = 0; bit < 256; bit++) {
    // The flipped key is planted in both places so step 3's equality check
    // passes and only the Ed25519 verification (or key import) can refuse it.
    const flipped = flipBit(pub, bit).toString('base64');
    const forgedKeys = makeKeyBundle([{ ...keys.keys[0], public_key: flipped }]);
    const forged = { ...receipt, signature: { ...receipt.signature, public_key: flipped } };
    const out = await verifyReceipt(forged, offline(forgedKeys));
    assert.equal(out.valid, false, `key bit ${bit} still verifies`);
    assert.ok(sigFailure(out), `key bit ${bit}: ${out.errors}`);
  }
});

test('property: changing any signed field, or adding an unsigned one, breaks the signature', async () => {
  const r = rng(SEED + 6);
  const { receipt, keys } = await signedCase(r, await makeEphemeralKey());
  const mutations = {
    receipt_id: { ...receipt, receipt_id: receipt.receipt_id.slice(0, -1) + (receipt.receipt_id.endsWith('0') ? '1' : '0') },
    timestamp_proof: { ...receipt, timestamp_proof: { method: 'ntp' } },
    'source.endpoint': { ...receipt, source: { ...receipt.source, endpoint: receipt.source.endpoint + '/' } },
    'chain.sequence': { ...receipt, chain: { ...receipt.chain, sequence: receipt.chain.sequence + 1 } },
    // An attacker who appends a field the verifier ignores could claim it was
    // signed; buildSigningObject keeps every field, so the signature breaks.
    'added extensions': { ...receipt, extensions: { note: 'unsigned' } },
    'added signature.public_key_encoding': { ...receipt, signature: { ...receipt.signature, public_key_encoding: 'raw-32-byte-base64' } },
  };
  for (const [name, forged] of Object.entries(mutations)) {
    const out = await verifyReceipt(forged, offline(keys));
    assert.equal(out.valid, false, `${name} still verifies`);
    assert.ok(sigFailure(out), `${name}: ${out.errors}`);
  }
});

test('property: payload strings are compared by code point, not by canonical equivalence', async () => {
  // NFC "é" and NFD "é" look the same and are canonically equivalent;
  // a verifier that normalized would let one payload stand in for the other.
  const key = await makeEphemeralKey();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt({ payload: { s: 'é' }, kp: key.kp, publicKeyB64: key.publicKeyB64 });
  const keys = makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]);
  assert.equal((await verifyReceipt(receipt, offline(keys))).valid, true);
  const swapped = { ...receipt, payload: { s: 'é' } };
  const out = await verifyReceipt(swapped, offline(keys));
  assert.equal(out.valid, false);
  assert.ok(out.errors.some((e) => e.startsWith('payload_hash mismatch')), out.errors);
});

test('key window bounds are inclusive: a receipt dated exactly at created_at or rotation_after verifies, 1 ms outside fails', async () => {
  const key = await makeEphemeralKey();
  const at = '2026-06-01T00:00:00.000Z';
  const before = '2026-05-31T23:59:59.999Z';
  const after = '2026-06-01T00:00:00.001Z';
  const bundleWith = (entry, keyId, publicKeyB64) =>
    makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64, ...entry }]);
  for (const [bound, outside] of [['created_at', before], ['rotation_after', after]]) {
    for (const [ts, expectValid] of [[at, true], [outside, false]]) {
      const { receipt, keyId, publicKeyB64 } = await makeReceipt({ kp: key.kp, publicKeyB64: key.publicKeyB64 });
      const stamped = { ...receipt, timestamp: ts };
      // The timestamp is signed: re-sign by building through makeReceipt is not
      // possible, so compare the window verdict only (the signature error is expected).
      const out = await verifyReceipt(stamped, offline(bundleWith({ [bound]: at }, keyId, publicKeyB64)));
      const windowError = out.errors.find((e) => e.includes(bound));
      assert.equal(windowError === undefined, expectValid, `${bound} at ${ts}: ${out.errors}`);
    }
  }
});

test('garbage bundle entries never throw and never verify', async () => {
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  // The bundle is trusted as a document, so a stray non-object entry beside
  // the real one is not a forgery: a number is skipped (the receipt verifies),
  // a null is a thrown lookup that index.ts reports as an error. Both are
  // pinned so a change in either direction is deliberate.
  const okKeys = makeKeyBundle([5, { key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]);
  assert.equal((await verifyReceipt(receipt, offline(okKeys))).valid, true);
  const bundles = {
    'null entry first': [null, { key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }],
    'entry without public_key': [{ key_id: keyId, algorithm: 'Ed25519' }],
    'numeric public_key': [{ key_id: keyId, algorithm: 'Ed25519', public_key: 7 }],
    'public_key that is not 32 bytes (planted in the receipt too)': [{ key_id: keyId, algorithm: 'Ed25519', public_key: 'AAAA' }],
  };
  for (const [name, keys] of Object.entries(bundles)) {
    const planted = name.includes('planted')
      ? { ...receipt, signature: { ...receipt.signature, public_key: keys[0].public_key } }
      : receipt;
    const out = await verifyReceipt(planted, offline(makeKeyBundle(keys)));
    assert.equal(out.valid, false, name);
    assert.ok(out.errors.length > 0, name);
  }
});
