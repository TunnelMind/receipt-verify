/**
 * verdict-lib/hash.js — the byte helpers the verdict kernel needs
 * (verify-receipt.js, log.js). bytesToHex and sha256HexPrefixed are the
 * package's own (dist/index.js, so `npm run build` first) re-exported here,
 * so the kernel and the verifier hash with one implementation. Only what the
 * kernel calls lives here; the service file this was vendored from
 * (tunnelmind-data-api api/utils/hash.js) carries more.
 * Inputs are untrusted strings from a receipt: b64ToBytes throws on anything
 * but standard base64. hexToBytes is no validator: a non-hex pair becomes 0
 * (Uint8Array stores parseInt's NaN as 0), a leading sign or space is
 * half-read ("+f" and " f" give 0x0f), and a non-string throws. Its only
 * caller (log.js nodeHash) hashes the bytes into a Merkle root that must
 * match the checkpoint's, inside verify-receipt.js's try, so a bad string
 * can re-spell a valid sibling hash but never make an invalid proof pass.
 */

import { bytesToHex, sha256HexPrefixed } from '../../dist/index.js';
export { bytesToHex, sha256HexPrefixed };

/** Hex string (`0x`-prefix tolerated) → raw bytes. */
export function hexToBytes(h) {
  const s = h.startsWith('0x') || h.startsWith('0X') ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

/**
 * Standard base64 → bytes, exactly as the package's src/index.ts decodes
 * signatures and keys: the spec says base64, and a decoder tolerant of
 * base64url would let a receipt pass this kernel and fail verifyReceipt().
 * A `-` or `_` throws.
 * @param {string} s
 * @returns {Uint8Array}
 */
export function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
