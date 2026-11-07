// Byte helpers shared by index.ts (receipt signatures) and log.ts (signed
// tree heads), so both read base64 by the same rule: forgiving for a public
// key from a pinned bundle, canonical-only for a signature value.

/** Standard base64 → bytes. atob() throws on `-`/`_` (base64url) and junk,
 *  but forgives ASCII whitespace, a missing `=` pad and unused low bits in
 *  the last character; signatureBytes below closes those for the one field
 *  where the spelling matters. */
export function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** `signature.value` → bytes, accepting only the canonical padded spelling
 *  (the bytes re-encode to the same string). The signature does not cover
 *  its own value, and the chain links on the SHA-256 of that string, so a
 *  forgiving decode would let one signature travel under many strings that
 *  all verify and each hash to a different chain link. */
export function signatureBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bytes = b64ToBytes(b64);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  if (btoa(bin) !== b64) throw new Error('signature.value is not canonical standard base64');
  return bytes;
}

/** Coerce TextEncoder output (ArrayBufferLike-backed) to ArrayBuffer-backed
 *  Uint8Array so SubtleCrypto's strict BufferSource typing is satisfied. */
export function toAB(u: Uint8Array): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(u.byteLength);
  new Uint8Array(buf).set(u);
  return new Uint8Array(buf);
}
