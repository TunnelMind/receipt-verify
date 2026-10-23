/**
 * verdict-lib/verify-receipt.js — the offline verdict verifier's kernel.
 * Dialect: a Reconciliation Verdict receipt = a Receipt v1.0 envelope (the
 * package verifies that part) whose payload holds claim/conduct/reconciliation
 * plus a `self_verification` triple (inclusion proof, checkpoint, witness
 * cosignatures), which is outside the signed envelope. Returns a per-check
 * pass/fail report; `ok` only when every check passes. Never throws on any
 * receipt shape — every primitive that can throw is caught into a failed check.
 * Trust: only what the caller pins — the issuer bundle (default: the shipped
 * pinned bundle), `logKey`, `witnessKeys`; with no witness/log key pinned,
 * the bundle's usable entries stand in, matched by key_id. Every key carried
 * inside the receipt, checkpoint or cosig is attacker-controlled and is never
 * verified against. No revocation feed and no strength ceiling here: a verdict
 * receipt has neither contract (the four-tier validation still applies).
 * Pure: globalThis.crypto + the same reconcile()/Merkle code the service runs;
 * no fetch, env or bindings. Callers: scripts/verify-verdict.mjs (argv/IO
 * only) and the tests. Needs the built package (dist/, `npm run build`).
 */

import { reconcile } from './reconcile.js';
import { verifyInclusion, leafHash } from './log.js';
import { canonicalize, canonicalizeBytes } from './jcs.js';
import { sha256HexPrefixed, b64ToBytes } from './hash.js';
import { PINNED_KEY_BUNDLE } from '../../dist/pinned-keys.js';
import { verifyReceipt as verifyEnvelope } from '../../dist/index.js';

const subtle = globalThis.crypto.subtle;

async function ed25519Verify(pubB64, sigB64, messageBytes) {
  try {
    const key = await subtle.importKey('raw', b64ToBytes(pubB64), { name: 'Ed25519' }, false, ['verify']);
    return await subtle.verify('Ed25519', key, b64ToBytes(sigB64), messageBytes);
  } catch { return false; }
}

const sameCanonical = (a, b) => canonicalize(a) === canonicalize(b);

// Pinned witness keys: base64 raw keys or { key_id, public_key } entries.
const normWitness = (list) => (Array.isArray(list) ? list : [])
  .map((k) => (typeof k === 'string' ? { public_key: k } : k))
  .filter((k) => k && typeof k.public_key === 'string');

/**
 * @param {object} receipt — a reconciliation receipt (with self_verification)
 * @param {object} [opts]
 * @param {object} [opts.keys] — issuer KeyBundle; defaults to the shipped pinned bundle
 * @param {string} [opts.logKey] — base64 raw Ed25519 key; only used when the
 *   checkpoint carries its own `signature` (the witness cosig is the checkpoint proof).
 *   Default: the usable `keys` entries whose key_id equals signature.key_id.
 * @param {Array<string|{key_id?:string,public_key:string}>} [opts.witnessKeys]
 *   Default: the usable `keys` entries, matched by cosig key_id. An explicit
 *   value (even []) replaces the default.
 * @returns {Promise<{ ok: boolean, checks: Array<{check,pass,detail}> }>}
 */
export async function verifyReceipt(receipt, { keys = PINNED_KEY_BUNDLE, logKey, witnessKeys } = {}) {
  const checks = [];
  // Default log/witness trust anchors: the bundle's usable entries (status
  // active or rotated; missing = active, as keyUsableAt). Revoked keys never count.
  const defaultPinned = (keys && Array.isArray(keys.keys) ? keys.keys : [])
    .filter((k) => k && typeof k.public_key === 'string' && ['active', 'rotated'].includes(k.status ?? 'active'))
    .map((k) => ({ key_id: k.key_id, public_key: k.public_key }));
  const add = (check, pass, detail) => checks.push({ check, pass, detail });

  if (!receipt || typeof receipt !== 'object' || !receipt.signature) {
    add('shape', false, 'not a receipt');
    return { ok: false, checks };
  }

  // 1. receipt signature — delegated to the package's verifyReceipt
  //    (src/index.ts), the one verifier of the envelope, so the kernel cannot
  //    drift from it: key_id resolved against the BUNDLE, usable status +
  //    [created_at, rotation_after] window, embedded public_key equal to it,
  //    Ed25519 over canonical(receipt minus payload and signature.value).
  //    self_verification is stripped first: it is not part of the signed
  //    envelope. payload_hash is check 2's: the package reports it as the
  //    only errors that start with "payload", so those are filtered out here.
  const sig = receipt.signature;
  const { self_verification: _sv, ...envelope } = receipt;
  const env = await verifyEnvelope(envelope, { keys, unsafeSkipRevocations: true, unsafeSkipStrengthCeiling: true });
  const sigErrors = env.errors.filter((e) => !e.startsWith('payload'));
  add('receipt_signature', sigErrors.length === 0, sigErrors.length ? sigErrors.join('; ') : `key_id=${sig.key_id}`);

  // 2. payload integrity.
  if (receipt.payload !== undefined && receipt.payload_hash) {
    // canonicalizeBytes throws on a lone surrogate; the kernel reports, never throws.
    let h;
    try { h = await sha256HexPrefixed(canonicalizeBytes(receipt.payload)); } catch (e) { add('payload_hash', false, e.message); h = null; }
    if (h !== null) add('payload_hash', h === receipt.payload_hash, h === receipt.payload_hash ? undefined : `recomputed ${h}`);
  } else {
    add('payload_hash', false, 'payload or payload_hash missing');
  }

  // 3 & 4. self-verification triple.
  const sv = receipt.self_verification;
  if (sv && sv.inclusion_proof && sv.checkpoint) {
    const bare = { ...receipt };
    delete bare.self_verification;
    const { leaf_index, tree_size, audit_path } = sv.inclusion_proof;
    let okIncl = false;
    let inclDetail;
    try { // canonicalizeBytes throws on a lone surrogate; the kernel reports, never throws
      const leaf = await leafHash(canonicalizeBytes(bare));
      okIncl = await verifyInclusion(leaf, leaf_index, tree_size, audit_path || [], sv.checkpoint.root_hash);
      inclDetail = okIncl ? `tree_size=${tree_size}` : 'leaf does not resolve to checkpoint root';
    } catch (e) { inclDetail = e.message; }
    add('log_inclusion', okIncl, inclDetail);

    // The issuer (tunnelmind-data-api api/roots/log.js + verdict.js) puts no
    // signature on the checkpoint itself: the root is signed by the witness
    // cosignatures below, made over canonical(checkpoint) incl. root_hash.
    // That pinned-witness check is the checkpoint proof and always runs. A
    // checkpoint that DOES carry its own signature (the STH scheme of
    // scripts/verify-log.mjs verifySth: Ed25519 over JCS(checkpoint minus
    // `signature`)) must also verify against the pinned --log-key, or by
    // default a usable bundle key with the signature's key_id.
    const cp = sv.checkpoint;
    if (cp.signature !== undefined) {
      const { signature, ...cpBody } = cp;
      const logKeys = logKey !== undefined ? [logKey].filter(Boolean)
        : defaultPinned.filter((k) => !signature?.key_id || k.key_id === signature.key_id).map((k) => k.public_key);
      if (logKeys.length === 0) {
        add('checkpoint_signature', false, 'checkpoint is signed but no pinned log key');
      } else if (!signature || signature.algorithm !== 'Ed25519' || !signature.value) {
        add('checkpoint_signature', false, 'checkpoint signature malformed');
      } else {
        let okCp = false;
        for (const k of logKeys) {
          if (await ed25519Verify(k, signature.value, canonicalizeBytes(cpBody))) { okCp = true; break; }
        }
        add('checkpoint_signature', okCp, okCp ? undefined : 'does not verify against pinned log key');
      }
    }

    // Witness cosignatures: each must verify under a PINNED witness key (by
    // key_id when the cosig names one; a pinned key without key_id matches any).
    const pinned = witnessKeys === undefined ? defaultPinned : normWitness(witnessKeys);
    // A cosig entry that is not an object (null, a string) is not a cosig:
    // reading .key_id off it would throw, and the kernel reports, never throws.
    const cosigs = (Array.isArray(sv.witness_cosignatures) ? sv.witness_cosignatures : [])
      .filter((c) => c && typeof c === 'object');
    const cpBytes = canonicalizeBytes(cp);
    if (pinned.length === 0) {
      add('witness_cosignatures', false, 'no pinned witness keys');
    } else if (cosigs.length === 0) {
      add('witness_cosignatures', false, 'none present');
    } else {
      let allOk = true;
      for (const c of cosigs) {
        const cands = pinned.filter((k) => !c.key_id || !k.key_id || k.key_id === c.key_id);
        let okc = false;
        for (const k of cands) {
          if (c.value && await ed25519Verify(k.public_key, c.value, cpBytes)) { okc = true; break; }
        }
        if (!okc) allOk = false;
      }
      add('witness_cosignatures', allOk, `${cosigs.length} cosig(s)${allOk ? '' : '; not all verify against pinned witness keys'}`);
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
    // reconcile() iterates claim.roots and canonicalize() refuses a lone
    // surrogate: a payload shaped to throw is a failed check, not a crash.
    let okRd = false;
    let rdDetail;
    try {
      const rederived = reconcile(claimSide, conduct);
      okRd = sameCanonical(rederived, payload.reconciliation);
      rdDetail = okRd ? `verdict.tier=${rederived.verdict.tier}` : 'reconcile() differs from published';
    } catch (e) { rdDetail = e.message; }
    add('verdict_rederivation', okRd, rdDetail);
  } else {
    add('verdict_rederivation', false, 'payload.claim / payload.reconciliation missing');
  }

  return { ok: checks.every((c) => c.pass), checks };
}
