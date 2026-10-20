import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { canonicalizeBytes } from '../dist/jcs.js';
import {
  verifyReceipt,
  fetchRevocations,
  clearKeyCache,
  clearRevocationCache,
  fetchKeyBundle,
  PINNED_KEY_BUNDLE,
  PINNED_KEYS_FETCHED_AT,
} from '../dist/index.js';
import {
  makeReceipt,
  makeEphemeralKey,
  makeKeyBundle,
  makeRevocations,
} from './_helpers.mjs';

function reset() {
  clearKeyCache();
  clearRevocationCache();
}

test('verifies a fresh receipt signed by the test key', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([
      { key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64, attestation_strength: 'software' },
    ]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, true, result.errors.join('; '));
  assert.deepEqual(result.errors, []);
  assert.equal(result.receipt_id, receipt.receipt_id);
  assert.equal(result.key_id, keyId);
  assert.equal(result.attestation_strength, 'software');
});

test('rejects a tampered payload', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt({ payload: { foo: 'bar' } });
  // Tamper after signing — payload_hash now stale.
  receipt.payload = { foo: 'EVIL' };
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('payload_hash mismatch')), 'expected payload_hash error');
});

test('rejects a tampered signature', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  // Flip one bit in the signature.
  const sig = Buffer.from(receipt.signature.value, 'base64');
  sig[0] ^= 0x01;
  receipt.signature.value = sig.toString('base64');
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('signature did not verify')), 'expected sig error');
});

test('rejects when key_id is missing from bundle (default strict)', async () => {
  reset();
  const { receipt } = await makeReceipt();
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([]), // empty bundle
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('not present in key bundle')));
});

// V001: an unresolved key_id used to become a warning here and the receipt
// verified against its own embedded key. allowKeyMismatch no longer rescues it.
test('allowKeyMismatch=true does not rescue a key_id missing from the bundle', async () => {
  reset();
  const { receipt } = await makeReceipt();
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([]),
    revocations: makeRevocations(),
    allowKeyMismatch: true,
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('not present in key bundle')));
});

test('rejects when key_bundle public_key disagrees with embedded public_key', async () => {
  reset();
  const { receipt, keyId } = await makeReceipt();
  // Same key_id but different public_key in the bundle.
  const other = await makeEphemeralKey();
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([
      { key_id: keyId, algorithm: 'Ed25519', public_key: other.publicKeyB64 },
    ]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('does not match')));
});

test('rejects when receipt attestation_strength exceeds key strength', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt({ attestationStrength: 'silicon-root' });
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([
      { key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64, attestation_strength: 'software' },
    ]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('attestation_strength ceiling')));
});

test('rejects when signing key is revoked AFTER the receipt was issued (precedes rotation = warn)', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  // Revoke key 1 hour AFTER the receipt's timestamp.
  const issuedAt = Date.parse(receipt.timestamp);
  const revokedAt = new Date(issuedAt + 3600_000).toISOString();
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations({
      revoked_keys: [{ key_id: keyId, revoked_at: revokedAt, reason: 'rotated' }],
    }),
  });
  // Receipt predates rotation → warn, but valid
  assert.equal(result.valid, true, result.errors.join('; '));
  assert.ok(result.warnings.some((w) => w.includes('rotated out of service')));
});

test('rejects when signing key was revoked BEFORE the receipt was issued', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  // Revoke key 1 hour BEFORE the receipt's timestamp.
  const issuedAt = Date.parse(receipt.timestamp);
  const revokedAt = new Date(issuedAt - 3600_000).toISOString();
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations({
      revoked_keys: [{ key_id: keyId, revoked_at: revokedAt, reason: 'compromised' }],
    }),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('revoked at')));
});

test('rejects when receipt_id is in revoked_receipts', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations({
      revoked_receipts: [{ receipt_id: receipt.receipt_id, revoked_at: receipt.timestamp, reason: 'issued in error' }],
    }),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('revoked at')));
});

// V001 (PoC E): offline mode used to verify against the embedded key, so any
// self-signed receipt passed. It now resolves against the pinned bundle.
test('offline mode (noFetchKeys + supplied revocations) rejects a self-signed receipt', async () => {
  reset();
  const { receipt } = await makeReceipt();
  const result = await verifyReceipt(receipt, {
    noFetchKeys: true,
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('not present in key bundle')));
});

// ── V001: key binding (forgeries from the audit PoC) ─────────────────────────

const PINNED_KEY_ID = PINNED_KEY_BUNDLE.keys[0].key_id;

// Re-sign after editing the signature block (makeReceipt always sets key_id).
async function resign(receipt, kp) {
  const { payload: _p, ...rest } = receipt;
  const { value: _v, ...sig } = receipt.signature;
  const bytes = canonicalizeBytes({ ...rest, signature: sig });
  receipt.signature.value = Buffer.from(
    await webcrypto.subtle.sign('Ed25519', kp.privateKey, bytes),
  ).toString('base64');
  return receipt;
}

function failingFetcher() {
  return async () => { throw new Error('network must not be touched'); };
}

test('pinned bundle ships the published key with a fetch date', () => {
  assert.equal(PINNED_KEY_ID, 'tm-receipt-2026-05');
  assert.equal(Buffer.from(PINNED_KEY_BUNDLE.keys[0].public_key, 'base64').length, 32);
  assert.ok(Number.isFinite(Date.parse(PINNED_KEYS_FETCHED_AT)));
});

test('PoC A: self-signed receipt with no key_id is invalid', async () => {
  reset();
  const { kp, publicKeyB64 } = await makeEphemeralKey();
  const { receipt } = await makeReceipt({ kp, publicKeyB64, attestationStrength: 'silicon-root' });
  delete receipt.signature.key_id;
  await resign(receipt, kp);
  const result = await verifyReceipt(receipt, {
    keys: PINNED_KEY_BUNDLE,
    revocations: makeRevocations(),
    fetcher: failingFetcher(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('key_id')));
});

test('PoC B: self-signed receipt with key_id "" is invalid', async () => {
  reset();
  const { kp, publicKeyB64 } = await makeEphemeralKey();
  const { receipt } = await makeReceipt({ kp, publicKeyB64, keyId: '', attestationStrength: 'silicon-root' });
  const result = await verifyReceipt(receipt, {
    keys: PINNED_KEY_BUNDLE,
    revocations: makeRevocations(),
    fetcher: failingFetcher(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('key_id')));
});

test('PoC E: self-signed receipt claiming the real key_id fails offline against the pinned bundle', async () => {
  reset();
  const { receipt } = await makeReceipt({ keyId: PINNED_KEY_ID });
  const result = await verifyReceipt(receipt, {
    noFetchKeys: true,
    revocations: makeRevocations(),
    fetcher: failingFetcher(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('does not match')));
  assert.ok(result.errors.some((e) => e.includes('signature did not verify')));
});

test('default path (no keys, no keysUrl) uses the pinned bundle without fetching', async () => {
  reset();
  const { receipt } = await makeReceipt({ keyId: PINNED_KEY_ID });
  const result = await verifyReceipt(receipt, {
    revocations: makeRevocations(),
    fetcher: failingFetcher(),
  });
  assert.equal(result.valid, false);
  assert.ok(!result.errors.some((e) => e.includes('fetch')), result.errors.join('; '));
  assert.ok(result.errors.some((e) => e.includes('signature did not verify')));
});

test('embedded public_key differing from the bundle is an error even if the signature is the bundle key\'s', async () => {
  reset();
  const signer = await makeEphemeralKey();
  const other = await makeEphemeralKey();
  const { receipt, keyId } = await makeReceipt({ kp: signer.kp, publicKeyB64: other.publicKeyB64 });
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: signer.publicKeyB64 }]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('does not match')));
  assert.ok(!result.errors.some((e) => e.includes('signature did not verify')), result.errors.join('; '));
});

test('TunnelMind-shaped receipt signed by a key in an injected bundle verifies', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt({
    keyId: PINNED_KEY_ID,
    lens: 'sigil',
    endpoint: '/v1/sigil/verify',
  });
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([
      { key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64, status: 'active', attestation_strength: 'software' },
    ]),
    revocations: makeRevocations(),
    fetcher: failingFetcher(),
  });
  assert.equal(result.valid, true, result.errors.join('; '));
  assert.deepEqual(result.warnings, []);
});

test('keysUrl is fetched through the injected fetcher', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  const bundle = makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]);
  const result = await verifyReceipt(receipt, {
    keysUrl: 'https://issuer.example/keys.json',
    fetcher: async () => new Response(JSON.stringify(bundle)),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, true, result.errors.join('; '));
});

// ── R002: the key-bundle cache is per URL with a TTL ──

test('two keysUrls served through one fetcher each verify against their own bundle', async () => {
  reset();
  const a = await makeReceipt();
  const b = await makeReceipt();
  const bundles = {
    'https://a.example/keys.json': makeKeyBundle([{ key_id: a.keyId, algorithm: 'Ed25519', public_key: a.publicKeyB64 }]),
    'https://b.example/keys.json': makeKeyBundle([{ key_id: b.keyId, algorithm: 'Ed25519', public_key: b.publicKeyB64 }]),
  };
  const fetcher = async (url) => new Response(JSON.stringify(bundles[url]));
  for (const [url, { receipt }] of [['https://a.example/keys.json', a], ['https://b.example/keys.json', b]]) {
    const result = await verifyReceipt(receipt, { keysUrl: url, fetcher, revocations: makeRevocations() });
    assert.equal(result.valid, true, `${url}: ${result.errors.join('; ')}`);
  }
});

test('ttlMs: 0 refetches the key bundle; the default TTL serves the cache', async () => {
  reset();
  let calls = 0;
  const fetcher = async () => { calls++; return new Response(JSON.stringify(makeKeyBundle([]))); };
  const url = 'https://ttl.example/keys.json';
  await fetchKeyBundle({ url, fetcher, ttlMs: 0 });
  await fetchKeyBundle({ url, fetcher, ttlMs: 0 });
  assert.equal(calls, 2);
  reset();
  calls = 0;
  await fetchKeyBundle({ url, fetcher });
  await fetchKeyBundle({ url, fetcher });
  assert.equal(calls, 1);
});

// ── V002: a failed bundle fetch is an error; offline uses the pinned bundle ──

test('PoC C: keysUrl fetch that throws makes the receipt invalid (error, not warning)', async () => {
  reset();
  const { receipt } = await makeReceipt({ keyId: PINNED_KEY_ID });
  const result = await verifyReceipt(receipt, {
    keysUrl: 'https://example.test/k.json',
    fetcher: async () => { throw new Error('boom'); },
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('key bundle fetch failed') && e.includes('boom')),
    result.errors.join('; '));
  assert.ok(!result.warnings.some((w) => w.includes('fetch')), result.warnings.join('; '));
});

test('keysUrl returning HTTP 500 makes the receipt invalid', async () => {
  reset();
  const { receipt } = await makeReceipt({ keyId: PINNED_KEY_ID });
  const result = await verifyReceipt(receipt, {
    keysUrl: 'https://example.test/k.json',
    fetcher: async () => new Response('', { status: 500 }),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('key bundle fetch failed') && e.includes('500')),
    result.errors.join('; '));
  assert.ok(!result.warnings.some((w) => w.includes('fetch')), result.warnings.join('; '));
});

test('noFetchKeys with keysUrl never calls the fetcher and resolves against the pinned bundle', async () => {
  reset();
  const { receipt } = await makeReceipt({ keyId: PINNED_KEY_ID });
  const result = await verifyReceipt(receipt, {
    keysUrl: 'https://example.test/k.json',
    noFetchKeys: true,
    fetcher: failingFetcher(),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(!result.errors.some((e) => e.includes('fetch')), result.errors.join('; '));
  assert.ok(result.errors.some((e) => e.includes('does not match')));
  assert.ok(result.errors.some((e) => e.includes('signature did not verify')));
});

// V003: allowKeyMismatch only switches to ANOTHER usable key in the bundle,
// matched by the receipt's embedded public_key; key windows always apply.
const DAY = 24 * 3600 * 1000;
const iso = (ms) => new Date(ms).toISOString();

async function mismatchCase(bEntryExtra = {}, { includeB = true, revocations = makeRevocations() } = {}) {
  const a = await makeEphemeralKey();
  const b = await makeEphemeralKey();
  // Signed by B, embeds B's public_key, but names key A.
  const { receipt } = await makeReceipt({ keyId: 'key-a', kp: b.kp, publicKeyB64: b.publicKeyB64 });
  const keys = [{ key_id: 'key-a', algorithm: 'Ed25519', public_key: a.publicKeyB64 }];
  if (includeB) {
    keys.push({ key_id: 'key-b', algorithm: 'Ed25519', public_key: b.publicKeyB64, status: 'active', ...bEntryExtra });
  }
  return verifyReceipt(receipt, {
    keys: makeKeyBundle(keys),
    revocations,
    allowKeyMismatch: true,
  });
}

test('allowKeyMismatch=true accepts a receipt whose public_key is another active bundle key, with a warning', async () => {
  reset();
  const result = await mismatchCase({
    created_at: iso(Date.now() - DAY),
    rotation_after: iso(Date.now() + DAY),
  });
  assert.equal(result.valid, true, result.errors.join('; '));
  assert.ok(result.warnings.some((w) => w.includes('key-a') && w.includes('key-b')), result.warnings.join('; '));
});

test('allowKeyMismatch=true rejects when the other bundle key is revoked', async () => {
  reset();
  const result = await mismatchCase({ status: 'revoked' });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('does not match')));
});

test('allowKeyMismatch=true rejects when the other key\'s window ended before the receipt', async () => {
  reset();
  const result = await mismatchCase({ status: 'rotated', rotation_after: iso(Date.now() - DAY) });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('does not match')));
});

test('allowKeyMismatch=true rejects when the other key\'s window starts after the receipt', async () => {
  reset();
  const result = await mismatchCase({ created_at: iso(Date.now() + DAY) });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('does not match')));
});

test('allowKeyMismatch=true rejects an embedded public_key absent from the bundle', async () => {
  reset();
  const result = await mismatchCase({}, { includeB: false });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('does not match')));
  assert.deepEqual(result.warnings, []);
});

async function windowCase(entryExtra) {
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  return verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64, ...entryExtra }]),
    revocations: makeRevocations(),
  });
}

test('rejects a receipt issued before its key\'s created_at', async () => {
  reset();
  const result = await windowCase({ created_at: iso(Date.now() + DAY) });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('precedes')), result.errors.join('; '));
});

test('rejects a receipt issued after its key\'s rotation_after', async () => {
  reset();
  const result = await windowCase({ status: 'rotated', rotation_after: iso(Date.now() - DAY) });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('rotation_after')), result.errors.join('; '));
});

test('rejects a receipt signed by a key whose bundle status is revoked', async () => {
  reset();
  const result = await windowCase({ status: 'revoked' });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('status is revoked')), result.errors.join('; '));
});

test('a key whose window covers the receipt verifies (active and rotated)', async () => {
  reset();
  for (const status of ['active', 'rotated']) {
    const result = await windowCase({
      status,
      created_at: iso(Date.now() - DAY),
      rotation_after: iso(Date.now() + DAY),
    });
    assert.equal(result.valid, true, `${status}: ${result.errors.join('; ')}`);
  }
});

test('rejects a receipt with an unparseable timestamp', async () => {
  reset();
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  receipt.timestamp = 'not-a-date';
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('timestamp')));
});

test('allowKeyMismatch=true rejects when the other key is revoked in the feed', async () => {
  reset();
  const result = await mismatchCase({}, {
    revocations: makeRevocations({
      revoked_keys: [{ key_id: 'key-b', revoked_at: iso(Date.now() - DAY), reason: 'compromised' }],
    }),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('signing key key-b revoked')), result.errors.join('; '));
});

// ── V005: revocation fails closed ────────────────────────────────────────────

async function pinnedLocalCase(opts) {
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  const keys = makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]);
  return verifyReceipt(receipt, { keys, ...opts });
}

test('a failed revocation feed fetch is an error, not a warning', async () => {
  reset();
  const result = await pinnedLocalCase({ fetcher: failingFetcher() });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('revocation feed fetch failed')), result.errors.join('; '));
  assert.ok(!result.warnings.some((w) => w.includes('revocation')));
});

test('unsafeSkipRevocations skips the check without fetching', async () => {
  reset();
  let calls = 0;
  const result = await pinnedLocalCase({
    unsafeSkipRevocations: true,
    fetcher: async () => { calls++; throw new Error('network must not be touched'); },
  });
  assert.equal(result.valid, true, result.errors.join('; '));
  assert.equal(calls, 0);
});

async function futureRevocationCase(reason) {
  const { receipt, keyId, publicKeyB64 } = await makeReceipt();
  // revoked_at is AFTER the (signer-chosen) receipt timestamp.
  const revokedAt = new Date(Date.parse(receipt.timestamp) + 3600_000).toISOString();
  return verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations({ revoked_keys: [{ key_id: keyId, revoked_at: revokedAt, reason }] }),
  });
}

test('a compromised key rejects even a receipt dated before revoked_at', async () => {
  reset();
  const result = await futureRevocationCase('compromise');
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('revoked at') && e.includes('compromise')), result.errors.join('; '));
});

test('a rotated key still accepts a receipt dated before revoked_at, with a warning', async () => {
  reset();
  const result = await futureRevocationCase('rotation');
  assert.equal(result.valid, true, result.errors.join('; '));
  assert.ok(result.warnings.some((w) => w.includes('rotated out of service')));
});

function countingFetcher() {
  const urls = [];
  const fetcher = async (url) => {
    urls.push(url);
    return new Response(JSON.stringify(makeRevocations()), { status: 200 });
  };
  return { urls, fetcher };
}

test('revocation cache is keyed by URL', async () => {
  reset();
  const { urls, fetcher } = countingFetcher();
  await fetchRevocations({ url: 'https://a.example/rev.json', fetcher });
  await fetchRevocations({ url: 'https://b.example/rev.json', fetcher });
  await fetchRevocations({ url: 'https://a.example/rev.json', fetcher });
  assert.deepEqual(urls, ['https://a.example/rev.json', 'https://b.example/rev.json']);
  clearRevocationCache();
  await fetchRevocations({ url: 'https://a.example/rev.json', fetcher });
  assert.equal(urls.length, 3);
});

test('revocation cache entries expire after ttlMs', async () => {
  reset();
  const { urls, fetcher } = countingFetcher();
  await fetchRevocations({ url: 'https://a.example/rev.json', fetcher, ttlMs: 0 });
  await fetchRevocations({ url: 'https://a.example/rev.json', fetcher, ttlMs: 0 });
  assert.equal(urls.length, 2);
});

// ── V006: JCS lone surrogates + opts.previous chain check ─────────────────────

test('canonicalize rejects lone surrogates in values and keys, accepts valid pairs', async () => {
  const { canonicalize } = await import('../dist/jcs.js');
  assert.throws(() => canonicalize('a\uD800b'), /lone surrogate/);
  assert.throws(() => canonicalize('a\uDC00b'), /lone surrogate/);
  assert.throws(() => canonicalize({ '\uDC00': 1 }), /lone surrogate/);
  assert.equal(canonicalize('😀'), '"😀"');
  assert.equal(canonicalize({ '😀': 1 }), '{"😀":1}');
});

test('a lone surrogate in the payload is an error, not a throw', async () => {
  reset();
  // Sign over U+FFFD, then swap in the lone surrogate TextEncoder would map to
  // it: without the guard the hash still matches and the receipt verifies.
  const { receipt, keyId, publicKeyB64 } = await makeReceipt({ payload: { s: 'a�b' } });
  receipt.payload = { s: 'a\uD800b' };
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('payload canonicalization failed')), result.errors.join('; '));
});

async function makeChainPair({ sequence = 1 } = {}) {
  const key = await makeEphemeralKey();
  const { receipt: prev, keyId } = await makeReceipt({ ...key, payload: { n: 0 } });
  // Issuer contract: sha256 over the UTF-8 bytes of prev.signature.value.
  const previous_receipt_hash = '0x' + Buffer.from(
    await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(prev.signature.value)),
  ).toString('hex');
  const { receipt } = await makeReceipt({ ...key, payload: { n: 1 }, chain: { previous_receipt_hash, sequence } });
  const opts = {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: key.publicKeyB64 }]),
    revocations: makeRevocations(),
  };
  return { prev, receipt, opts };
}

test('previous: a matching previous receipt gives no chain error', async () => {
  reset();
  const { prev, receipt, opts } = await makeChainPair();
  const result = await verifyReceipt(receipt, { ...opts, previous: prev });
  assert.equal(result.valid, true, result.errors.join('; '));
});

test('previous: a tampered previous signature is a hash mismatch error', async () => {
  reset();
  const { prev, receipt, opts } = await makeChainPair();
  const tampered = { ...prev, signature: { ...prev.signature, value: prev.signature.value + 'x' } };
  const result = await verifyReceipt(receipt, { ...opts, previous: tampered });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('chain.previous_receipt_hash mismatch')), result.errors.join('; '));
});

test('previous: a previous receipt without a signature value is an error, not a throw', async () => {
  reset();
  const { prev, receipt, opts } = await makeChainPair();
  const result = await verifyReceipt(receipt, { ...opts, previous: { ...prev, signature: {} } });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('previous receipt has no signature value')), result.errors.join('; '));
});

test('previous: a wrong sequence is an error', async () => {
  reset();
  const { prev, receipt, opts } = await makeChainPair({ sequence: 2 });
  const result = await verifyReceipt(receipt, { ...opts, previous: prev });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('chain.sequence mismatch')), result.errors.join('; '));
});

test('previous: a receipt with no chain is an error', async () => {
  reset();
  const { prev, receipt, opts } = await makeChainPair();
  delete receipt.chain;
  const result = await verifyReceipt(receipt, { ...opts, previous: prev });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes('previous supplied but receipt has no chain')), result.errors.join('; '));
});

// F2 (2026-10-19): the signature is standard base64 (spec §3); base64url is
// not accepted, here or in scripts/verdict-lib (which decoded both).
test('a base64url signature.value is invalid', async () => {
  reset();
  let made = await makeReceipt();
  // A signature with no + or / is the same string in both alphabets.
  while (!/[+/]/.test(made.receipt.signature.value)) made = await makeReceipt();
  const { receipt, keyId, publicKeyB64 } = made;
  receipt.signature.value = receipt.signature.value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: publicKeyB64 }]),
    revocations: makeRevocations(),
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.startsWith('signature verification failed')), result.errors.join('; '));
});
