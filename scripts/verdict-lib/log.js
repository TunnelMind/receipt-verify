/**
 * verdict-lib/log.js (from tunnelmind-data-api api/roots/log.js)
 *
 * RFC 6962-style Merkle primitives for the self-verification triple (ADR-001 §3).
 * Pure + zero-dep: leaf/node hashing and an inclusion-proof verifier — the
 * verifier half, which is what matters for invariant 5: `scripts/verify-verdict.mjs`
 * re-derives a verdict offline using exactly this code path, with only the
 * receipt bytes + witness keys. The service file's checkpoint builder (the
 * publisher's half) had no caller here and was dropped 2026-10-21.
 *
 * Domain-separated hashing (RFC 6962 §2.1):
 *   leaf hash  = SHA-256(0x00 || data)
 *   node hash  = SHA-256(0x01 || left || right)
 *
 * Bootstrap (ADR-001): the log is a 1-leaf tree per record — root == leaf hash,
 * audit_path === []. The verifier handles general multi-leaf proofs so adding a
 * real batched log later changes data, not this code.
 */

import { bytesToHex as hex, hexToBytes } from './hash.js';

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/** leaf hash = SHA-256(0x00 || data). `data` is bytes (the canonical receipt body). */
export async function leafHash(data) {
  return '0x' + hex(await sha256(concat(new Uint8Array([0x00]), data)));
}

/** node hash = SHA-256(0x01 || left || right). left/right are 0x-prefixed hex. */
export async function nodeHash(leftHex, rightHex) {
  const body = concat(new Uint8Array([0x01]), concat(hexToBytes(leftHex), hexToBytes(rightHex)));
  return '0x' + hex(await sha256(body));
}

/**
 * Verify an inclusion proof: recompute the Merkle root from the leaf + audit path
 * and check it equals the checkpoint root. RFC 6962 §2.1.1.
 *
 * @param {string} leafHex   — 0x-prefixed leaf hash
 * @param {number} index     — leaf_index
 * @param {number} treeSize  — tree_size
 * @param {string[]} auditPath — sibling hashes, leaf→root order
 * @param {string} rootHex   — expected checkpoint root_hash
 * @returns {Promise<boolean>}
 */
export async function verifyInclusion(leafHex, index, treeSize, auditPath, rootHex) {
  if (!Number.isInteger(index) || !Number.isInteger(treeSize) || index < 0 || index >= treeSize) {
    return false;
  }
  let computed = leafHex;
  let fn = index;          // node position within the current level
  let sn = treeSize - 1;   // last node index within the current level
  for (const sibling of auditPath) {
    if (sn === 0) return false;          // ran out of tree before path
    if (fn % 2 === 1 || fn === sn) {     // we are a right child (or rightmost odd node)
      computed = await nodeHash(sibling, computed);
      while (fn % 2 === 0 && sn !== 0) { fn >>= 1; sn >>= 1; } // skip up over left-only levels
    } else {
      computed = await nodeHash(computed, sibling);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && computed === rootHex;
}
