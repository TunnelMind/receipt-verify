/**
 * verdict-lib/jcs.js — RFC 8785 canonicalizer for the verdict kernel
 * (verify-receipt.js: payload hash, Merkle leaf, checkpoint bytes, verdict
 * re-derivation compare). canonicalize/canonicalizeBytes are the package's
 * own (src/jcs.ts via dist/index.js, so `npm run build` first) re-exported
 * here, so the kernel and the verifier canonicalize with one implementation:
 * the lone-surrogate refusal and the byte pinning to test/vectors/jcs.json
 * come with it (the service copy emits U+FFFD instead — a verdict receipt
 * carrying one therefore fails here, by design).
 * Input: untrusted parsed JSON from the receipt; throws on a lone surrogate
 * or non-finite number, and every caller in verify-receipt.js catches that
 * into a failed check. uuidv7 (RFC 9562 §5.7) rides along for the test
 * helpers, which mint receipt ids with it.
 */

import { bytesToHex } from './hash.js';
import { canonicalize, canonicalizeBytes } from '../../dist/index.js';
export { canonicalize, canonicalizeBytes };

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
