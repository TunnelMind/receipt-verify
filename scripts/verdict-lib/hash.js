/**
 * api/utils/hash.js
 *
 * SHA-256 + byte↔hex helpers — THE single home for these primitives.
 * (bytesToHex/hexToBytes were formerly re-rolled in ~12 files; fix here once.)
 * Uses the Web Crypto API available in Cloudflare Workers and Node ≥19.
 *
 * In this repo bytesToHex and sha256HexPrefixed are the package's own
 * (dist/index.js, `npm run build` first) and re-exported here, so the
 * kernel and the verifier hash with one copy (2026-10-19).
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

/** n random bytes as hex (2n chars). */
export function randomHex(nBytes) {
  const b = new Uint8Array(nBytes);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}

/**
 * SHA-256 hash a string. Returns lowercase hex.
 * @param {string} input
 * @returns {Promise<string>}
 */
export async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  return bytesToHex(await crypto.subtle.digest('SHA-256', data));
}

/** HMAC-SHA256 over `message` keyed by `secret`, lowercase hex (webhook-signature convention). */
export async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return bytesToHex(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

/**
 * Generate a new API key in the format: tm_live_<32 random hex chars>
 * @returns {string}
 */
export function generateApiKey() {
  return 'tm_live_' + randomHex(16);
}

/**
 * Constant-time string equality for secret comparison (e.g. ADMIN_KEY). Compares
 * without early-exit, so verification leaks no per-byte timing signal about the
 * secret. A length mismatch returns false immediately — acceptable for
 * high-entropy secrets, where length is not meaningfully sensitive.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function timingSafeEqual(a, b) {
  const sa = String(a ?? '');
  const sb = String(b ?? '');
  if (sa.length === 0 || sb.length === 0 || sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  return diff === 0;
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

/**
 * Bytes → base64url (no padding). Accepts Uint8Array or ArrayBuffer.
 * Formerly re-rolled in eat-token, sigil-token, x402/cdp-auth,
 * compliance/exporters and roots/key.
 * @param {Uint8Array|ArrayBuffer} bytes
 * @returns {string}
 */
export function bytesToB64url(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
