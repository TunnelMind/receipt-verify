// Test helpers — synthesize a valid Receipt v1.0 envelope offline, signed
// by an ephemeral keypair. Mirrors the issuer-side wrap logic byte-for-byte
// so we don't pull tunnelmind-data-api or scry-server as a test dep.

import { webcrypto } from 'node:crypto';
import { canonicalize, canonicalizeBytes } from '../dist/jcs.js';
// The package's own hash helper and the kernel's uuidv7, so fixtures are
// hashed and minted by the code under test, not by a parallel copy.
import { sha256HexPrefixed } from '../dist/index.js';
import { uuidv7 } from '../scripts/verdict-lib/jcs.js';

const subtle = webcrypto.subtle;

export async function makeEphemeralKey() {
  const kp = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const jwkPub = await subtle.exportKey('jwk', kp.publicKey);
  const xB64u = jwkPub.x;
  const xB64  = xB64u.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (xB64u.length % 4)) % 4);
  return { kp, publicKeyB64: xB64 };
}

export async function makeReceipt({
  payload = { hello: 'world' },
  keyId   = 'test-receipt-2026-05',
  nodeOai = 'OAI-2026-0000201',
  lens    = 'tracker',
  endpoint = '/v1/test/echo',
  attestationStrength = 'software',
  chain = { previous_receipt_hash: null, sequence: 0 },
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
    chain,
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
