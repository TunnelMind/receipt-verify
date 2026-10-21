/**
 * verdict-lib/hash.js (from tunnelmind-data-api api/utils/hash.js)
 *
 * The byte helpers the verdict kernel needs. bytesToHex and sha256HexPrefixed
 * are the package's own (dist/index.js, `npm run build` first) and re-exported
 * here, so the kernel and the verifier hash with one copy (2026-10-19). The
 * service file's other helpers (HMAC, API-key generation, timing-safe compare,
 * base64url) had no caller in this repo and were dropped 2026-10-21.
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
 * signatures and keys (2026-10-19; was tolerant of base64url, so a receipt
 * could pass this kernel and fail verifyReceipt()). The spec says base64;
 * a `-` or `_` throws.
 * @param {string} s
 * @returns {Uint8Array}
 */
export function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
