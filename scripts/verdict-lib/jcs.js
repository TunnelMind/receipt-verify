/**
 * verdict-lib/jcs.js — RFC 8785 canonicalizer for the verdict kernel
 * (verify-receipt.js: payload hash, Merkle leaf, checkpoint bytes, verdict
 * re-derivation compare). Vendored from tunnelmind-data-api api/utils/jcs.js
 * so the kernel hashes exactly what the service hashed; pinned byte-for-byte
 * to src/jcs.ts by test/vectors/jcs.json (test/jcs-vectors.test.mjs), with
 * the same lone-surrogate refusal (the service copy emits U+FFFD instead —
 * a verdict receipt carrying one therefore fails here, by design).
 * Input: untrusted parsed JSON from the receipt; throws on a lone surrogate
 * or non-finite number, and every caller in verify-receipt.js catches that
 * into a failed check. uuidv7 (RFC 9562 §5.7) rides along for the test
 * helpers, which mint receipt ids with it.
 */

import { bytesToHex } from './hash.js';

const ESC = { '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t' };

function encodeString(s) {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0);
    // Same guard as src/jcs.ts: the iterator yields valid pairs as one code
    // point > 0xFFFF, so a code in this range is a lone surrogate, which
    // TextEncoder would map to U+FFFD and collide two strings' bytes.
    if (code >= 0xd800 && code <= 0xdfff) throw new Error('JCS: lone surrogate in string');
    if (ch in ESC) out += ESC[ch];
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

export function canonicalize(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`JCS: non-finite number ${value}`);
    return String(value);
  }
  if (typeof value === 'string') return encodeString(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys.map((k) => encodeString(k) + ':' + canonicalize(value[k])).join(',') + '}';
  }
  throw new Error(`JCS: unsupported type ${typeof value}`);
}

export function canonicalizeBytes(value) {
  return new TextEncoder().encode(canonicalize(value));
}

/** uuidv7 — RFC 9562 §5.7, WebCrypto randomness. */
export function uuidv7(now = Date.now()) {
  const ms = BigInt(now);
  const r = crypto.getRandomValues(new Uint8Array(10));
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
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
