import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyReceipt,
  clearKeyCache,
  clearRevocationCache,
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

test('demotes key_id mismatch to warning when allowKeyMismatch=true', async () => {
  reset();
  const { receipt } = await makeReceipt();
  const result = await verifyReceipt(receipt, {
    keys: makeKeyBundle([]),
    revocations: makeRevocations(),
    allowKeyMismatch: true,
  });
  assert.equal(result.valid, true, result.errors.join('; '));
  assert.ok(result.warnings.some((w) => w.includes('not present in key bundle')));
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

test('offline mode (noFetchKeys + noFetchRevocations) verifies pure crypto only', async () => {
  reset();
  const { receipt } = await makeReceipt();
  const result = await verifyReceipt(receipt, {
    noFetchKeys: true,
    noFetchRevocations: true,
  });
  assert.equal(result.valid, true, result.errors.join('; '));
  assert.deepEqual(result.warnings, []);
});
