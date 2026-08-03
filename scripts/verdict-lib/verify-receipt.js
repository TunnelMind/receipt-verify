/**
 * api/roots/verify-receipt.js
 *
 * The pure, importable core of the standalone offline verdict verifier
 * (ADR-001 invariant 5). Given a reconciliation receipt + the witness public
 * keys carried INSIDE it, returns a per-check pass/fail report with no service
 * call. The CLI (scripts/verify-verdict.mjs) is just argv/IO around this; the
 * test suite imports it directly.
 *
 * Pure: uses globalThis.crypto + the same reconcile()/Merkle code the service
 * runs. No fetch, no env, no Worker bindings.
 */

import { reconcile } from './reconcile.js';
import { verifyInclusion, leafHash } from './log.js';
import { canonicalize, canonicalizeBytes } from './jcs.js';
import { sha256HexPrefixed, b64ToBytes } from './hash.js';

const subtle = globalThis.crypto.subtle;

async function ed25519Verify(pubB64, sigB64, messageBytes) {
  try {
    const key = await subtle.importKey('raw', b64ToBytes(pubB64), { name: 'Ed25519' }, false, ['verify']);
    return await subtle.verify('Ed25519', key, b64ToBytes(sigB64), messageBytes);
  } catch { return false; }
}

const sameCanonical = (a, b) => canonicalize(a) === canonicalize(b);

/**
 * @param {object} receipt — a reconciliation receipt (with self_verification)
 * @returns {Promise<{ ok: boolean, checks: Array<{check,pass,detail}> }>}
 */
export async function verifyReceipt(receipt) {
  const checks = [];
  const add = (check, pass, detail) => checks.push({ check, pass, detail });

  if (!receipt || typeof receipt !== 'object' || !receipt.signature) {
    add('shape', false, 'not a receipt');
    return { ok: false, checks };
  }

  // 1. receipt signature — over canonical(receipt minus payload & self_verification),
  //    signature.value blank (mirrors wrapReceipt's signing object exactly).
  const sig = receipt.signature;
  if (sig.value && sig.public_key) {
    const signingObject = { ...receipt };
    delete signingObject.payload;
    delete signingObject.self_verification;
    signingObject.signature = { algorithm: sig.algorithm, key_id: sig.key_id, public_key: sig.public_key };
    const okSig = await ed25519Verify(sig.public_key, sig.value, canonicalizeBytes(signingObject));
    add('receipt_signature', okSig, okSig ? `key_id=${sig.key_id}` : 'Ed25519 signature does not verify');
  } else {
    add('receipt_signature', false, 'unsigned (signature.value/public_key missing)');
  }

  // 2. payload integrity.
  if (receipt.payload !== undefined && receipt.payload_hash) {
    const h = await sha256HexPrefixed(canonicalizeBytes(receipt.payload));
    add('payload_hash', h === receipt.payload_hash, h === receipt.payload_hash ? undefined : `recomputed ${h}`);
  } else {
    add('payload_hash', false, 'payload or payload_hash missing');
  }

  // 3 & 4. self-verification triple.
  const sv = receipt.self_verification;
  if (sv && sv.inclusion_proof && sv.checkpoint) {
    const bare = { ...receipt };
    delete bare.self_verification;
    const leaf = await leafHash(canonicalizeBytes(bare));
    const { leaf_index, tree_size, audit_path } = sv.inclusion_proof;
    const okIncl = await verifyInclusion(leaf, leaf_index, tree_size, audit_path || [], sv.checkpoint.root_hash);
    add('log_inclusion', okIncl, okIncl ? `tree_size=${tree_size}` : 'leaf does not resolve to checkpoint root');

    const cosigs = Array.isArray(sv.witness_cosignatures) ? sv.witness_cosignatures : [];
    const cpBytes = canonicalizeBytes(sv.checkpoint);
    if (cosigs.length === 0) {
      add('witness_cosignatures', false, 'none present');
    } else {
      let allOk = true;
      for (const c of cosigs) {
        const okc = !!(c.public_key && c.value) && await ed25519Verify(c.public_key, c.value, cpBytes);
        if (!okc) allOk = false;
      }
      add('witness_cosignatures', allOk, `${cosigs.length} cosig(s)`);
    }
  } else {
    add('self_verification', false, 'inclusion_proof / checkpoint missing');
  }

  // 5. verdict re-derivation — same reconcile() the service ran.
  const payload = receipt.payload;
  if (payload && payload.claim && payload.reconciliation) {
    const claimSide = {
      roots: payload.claim.roots || [],
      best_verified_tier: payload.claim.best_verified_tier,
      key_control_proven: payload.claim.key_control_proven,
    };
    const conduct = payload.conduct && payload.conduct.available !== false ? payload.conduct : null;
    const rederived = reconcile(claimSide, conduct);
    const okRd = sameCanonical(rederived, payload.reconciliation);
    add('verdict_rederivation', okRd, okRd ? `verdict.tier=${rederived.verdict.tier}` : 'reconcile() differs from published');
  } else {
    add('verdict_rederivation', false, 'payload.claim / payload.reconciliation missing');
  }

  return { ok: checks.every((c) => c.pass), checks };
}
