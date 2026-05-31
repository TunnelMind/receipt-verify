// Test helpers — synthesize a valid Receipt v1.0 envelope offline, signed
// by an ephemeral keypair. Mirrors the issuer-side wrap logic byte-for-byte
// so we don't pull tunnelmind-data-api or scry-server as a test dep.

import { webcrypto } from 'node:crypto';
import { canonicalize, canonicalizeBytes } from '../dist/jcs.js';

const subtle = webcrypto.subtle;

const hex = (buf) =>
  Array.from(new Uint8Array(buf)).map((x) => x.toString(16).padStart(2, '0')).join('');

async function sha256HexPrefixed(bytes) {
  return '0x' + hex(await subtle.digest('SHA-256', bytes));
}

export async function makeEphemeralKey() {
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const jwkPub = await subtle.exportKey('jwk', kp.publicKey);
  const xB64u = jwkPub.x;
  const xB64  = xB64u.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (xB64u.length % 4)) % 4);
  return { kp, publicKeyB64: xB64 };
}

function uuidv7() {
  const ms = BigInt(Date.now());
  const r = webcrypto.getRandomValues(new Uint8Array(10));
  const b = new Uint8Array(16);
  b[0] = Number((ms >> 40n) & 0xffn);
  b[1] = Number((ms >> 32n) & 0xffn);
  b[2] = Number((ms >> 24n) & 0xffn);
  b[3] = Number((ms >> 16n) & 0xffn);
  b[4] = Number((ms >> 8n) & 0xffn);
  b[5] = Number(ms & 0xffn);
  b[6] = 0x70 | (r[0] & 0x0f);
  b[7] = r[1];
  b[8] = 0x80 | (r[2] & 0x3f);
  b[9] = r[3];
  for (let i = 10; i < 16; i++) b[i] = r[i - 6];
  const h = hex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export async function makeReceipt({
  payload = { hello: 'world' },
  keyId   = 'test-receipt-2026-05',
  nodeOai = 'OAI-2026-0000201',
  lens    = 'tracker',
  endpoint = '/v1/test/echo',
  attestationStrength = 'software',
  kp,
  publicKeyB64,
} = {}) {
  if (!kp || !publicKeyB64) {
    const fresh = await makeEphemeralKey();
    kp = fresh.kp;
    publicKeyB64 = fresh.publicKeyB64;
  }
  const payload_hash = await sha256HexPrefixed(canonicalizeBytes(payload));
  const receipt = {
    receipt_version: '1.0',
    receipt_id: uuidv7(),
    timestamp: new Date().toISOString(),
    timestamp_proof: { method: 'none' },
    source: { lens, endpoint, node_id: nodeOai },
    attestation_strength: attestationStrength,
    payload_hash,
    payload,
    chain: { previous_receipt_hash: null, sequence: 0 },
    signature: {
      algorithm: 'Ed25519',
      key_id: keyId,
      public_key: publicKeyB64,
    },
  };
  const signingObject = { ...receipt };
  delete signingObject.payload;
  signingObject.signature = { ...receipt.signature };
  const sig = await subtle.sign('Ed25519', kp.privateKey, canonicalizeBytes(signingObject));
  receipt.signature.value = Buffer.from(sig).toString('base64');
  return { receipt, keyId, publicKeyB64 };
}

export function makeKeyBundle(entries) {
  return {
    service: 'test',
    spec: 'https://tunnelmind.ai/standards/receipt-format/v1',
    format_version: '1.0',
    updated_at: new Date().toISOString(),
    keys: entries,
  };
}

export function makeRevocations({ revoked_keys = [], revoked_receipts = [] } = {}) {
  return {
    feed_version: 1,
    updated_at: new Date().toISOString(),
    revoked_keys,
    revoked_receipts,
  };
}

// Sanity export so test files can validate against canonicalize directly
export { canonicalize };
