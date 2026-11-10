// Generates test/vectors/receipt-v1/: the Receipt v1.0 vectors shared with
// the Rust verifier (rune-record), which reads the same files unchanged.
// Run `npm run build` first (it needs dist/jcs.js), then
// `node scripts/gen-receipt-v1-vectors.mjs`. Output is byte-stable: keys come
// from fixed public seeds, ids and timestamps are literals, and Ed25519
// signatures are deterministic, so a re-run must leave git clean.
//
// Imports only node builtins and the package canonicalizer, so the bytes a
// vector signs are the bytes both verifiers canonicalize.

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { canonicalizeBytes } from '../dist/jcs.js';

const OUT = new URL('../test/vectors/receipt-v1/', import.meta.url);
const SEED_STRING = 'receipt-verify receipt-v1 test vectors';
const SEED_NOTE = 'test-only key material, public, never used to sign anything real';
// RFC 8410 PKCS#8 wrapper for a raw 32-byte Ed25519 seed.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const sha256 = (b) => createHash('sha256').update(b).digest();

// Seed = sha256("<SEED_STRING>:<key_id>"); anyone can rebuild the private key.
function keyFor(keyId) {
  const seed = sha256(`${SEED_STRING}:${keyId}`);
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const x = createPublicKey(privateKey).export({ format: 'jwk' }).x;
  return { privateKey, publicKeyB64: Buffer.from(x, 'base64url').toString('base64') };
}

const KEYS = Object.fromEntries(['vec-valid', 'vec-expired', 'vec-revoked'].map((id) => [id, keyFor(id)]));

const keys = {
  service: 'receipt-verify test vectors',
  spec: 'https://tunnelmind.ai/standards/receipt-format/v1',
  format_version: '1.0',
  updated_at: '2026-03-01T00:00:00Z',
  keys: [
    { key_id: 'vec-valid', algorithm: 'Ed25519', public_key: KEYS['vec-valid'].publicKeyB64,
      status: 'active', created_at: '2025-01-01T00:00:00Z', attestation_strength: 'software' },
    { key_id: 'vec-expired', algorithm: 'Ed25519', public_key: KEYS['vec-expired'].publicKeyB64,
      status: 'rotated', created_at: '2025-01-01T00:00:00Z', rotation_after: '2026-01-01T00:00:00Z',
      attestation_strength: 'software' },
    // Active in the bundle: only the revocation feed revokes it, so that is its one error.
    { key_id: 'vec-revoked', algorithm: 'Ed25519', public_key: KEYS['vec-revoked'].publicKeyB64,
      status: 'active', created_at: '2025-01-01T00:00:00Z', attestation_strength: 'software' },
  ],
};

const revocations = {
  feed_version: 1,
  updated_at: '2026-03-01T00:00:00Z',
  revoked_keys: [{ key_id: 'vec-revoked', revoked_at: '2026-02-01T00:00:00Z', reason: 'compromise' }],
  revoked_receipts: [],
};

// Same envelope and signing rule as test/_helpers.mjs makeReceipt; `mutate`
// edits the envelope before signing, so each defect is still correctly signed.
function makeReceipt({ n, keyId = 'vec-valid', signer = keyId, payload = { hello: 'world' }, mutate }) {
  const receipt = {
    receipt_version: '1.0',
    receipt_id: `019c0000-0000-7000-8000-0000000000${String(n).padStart(2, '0')}`,
    timestamp: '2026-03-01T00:00:00Z',
    timestamp_proof: { method: 'none' },
    source: { lens: 'tracker', endpoint: '/v1/test/echo', node_id: 'OAI-2026-0000201' },
    attestation_strength: 'software',
    payload_hash: '0x' + sha256(canonicalizeBytes(payload)).toString('hex'),
    payload,
    chain: { previous_receipt_hash: null, sequence: 0 },
    signature: { algorithm: 'Ed25519', key_id: keyId, public_key: KEYS[signer].publicKeyB64 },
  };
  if (mutate) mutate(receipt);
  const { payload: _p, ...signingObject } = receipt;
  signingObject.signature = { ...receipt.signature };
  receipt.signature.value = sign(null, canonicalizeBytes(signingObject), KEYS[signer].privateKey).toString('base64');
  return receipt;
}

const text = (r) => JSON.stringify(r, null, 2) + '\n';

// The repeated member keeps the same value, so the receipt is otherwise valid
// and the duplicate is its only defect.
const dup = text(makeReceipt({ n: 9 })).replace('  "receipt_version": "1.0",\n', (line) => line + line);
if (!dup.includes('"receipt_version": "1.0",\n  "receipt_version"')) throw new Error('duplicate_key: member not repeated');

const files = {
  valid:              text(makeReceipt({ n: 1 })),
  unknown_key:        text(makeReceipt({ n: 2, keyId: 'vec-unknown', signer: 'vec-valid' })),
  expired_key:        text(makeReceipt({ n: 3, keyId: 'vec-expired' })),
  revoked_key:        text(makeReceipt({ n: 4, keyId: 'vec-revoked' })),
  tier_too_high:      text(makeReceipt({ n: 5, mutate: (r) => { r.attestation_strength = 'tee-tpm'; } })),
  missing_public_key: text(makeReceipt({ n: 6, mutate: (r) => { delete r.signature.public_key; } })),
  missing_receipt_id: text(makeReceipt({ n: 7, mutate: (r) => { delete r.receipt_id; } })),
  float_payload:      text(makeReceipt({ n: 8, payload: { value: 1.5 } })),
  duplicate_key:      dup,
  bad_timestamp:      text(makeReceipt({ n: 10, mutate: (r) => { r.timestamp = 'not-a-timestamp'; } })),
};

const manifest = {
  about: 'Receipt v1.0 cross-implementation vectors: receipt-verify (JS) and rune-record (Rust) read these files unchanged. '
    + 'Each <case>.json is raw receipt bytes with one defect; verify it with `keys` and `revocations` below and expect '
    + 'the named verdict (exactly one error for every case but valid). Generated by scripts/gen-receipt-v1-vectors.mjs.',
  seed_note: SEED_NOTE,
  seed_derivation: `Ed25519 seed = sha256("${SEED_STRING}:<key_id>")`,
  keys,
  revocations,
  cases: Object.keys(files).map((name) => ({ name, file: `${name}.json`, expect: name })),
};

mkdirSync(OUT, { recursive: true });
writeFileSync(new URL('cases.json', OUT), text(manifest));
for (const [name, body] of Object.entries(files)) writeFileSync(new URL(`${name}.json`, OUT), body);
