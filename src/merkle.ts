// RFC 6962 / RFC 9162 Merkle primitives for the receipt transparency log,
// on WebCrypto so they run wherever verifyReceipt() runs (Node >=20,
// Workers, Deno, Bun). Hashing: leaf = SHA-256(0x00 || data), node =
// SHA-256(0x01 || left || right) (RFC 6962 §2.1). Verification follows
// RFC 9162 §2.1.3.2 (inclusion) and §2.1.4.2 (consistency).
// Fail closed: malformed input (non-integer sizes, wrong-length hashes,
// out-of-range indices, a proof of the wrong length) returns false, never
// throws. These functions verify the math only; whether a root is TRUSTED is
// decided in log.ts, which only accepts roots from a signed tree head.
// scripts/verify-log.mjs keeps an independent node:crypto implementation on
// purpose; test/log.test.mjs checks both against a third, recursive reference.

const subtle = globalThis.crypto.subtle;

export const HASH_LENGTH = 32;

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(new ArrayBuffer(n));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', concat(...parts)));
}

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

/** RFC 6962 leaf hash of the leaf's content bytes. */
export function leafHash(data: Uint8Array): Promise<Uint8Array> {
  return sha256(LEAF_PREFIX, data);
}

/** RFC 6962 interior node hash. */
export function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(NODE_PREFIX, left, right);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] as number) ^ (b[i] as number);
  return d === 0;
}

/** Strict hex → 32-byte hash. Accepts an optional `0x` prefix and either
 *  case; anything else (odd length, non-hex, wrong length, non-string)
 *  returns null. */
export function parseHash(s: unknown): Uint8Array | null {
  if (typeof s !== 'string') return null;
  const h = s.startsWith('0x') ? s.slice(2) : s;
  if (h.length !== HASH_LENGTH * 2 || !/^[0-9a-fA-F]+$/.test(h)) return null;
  const out = new Uint8Array(HASH_LENGTH);
  for (let i = 0; i < HASH_LENGTH; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function validSize(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
}

function validHashes(xs: unknown): xs is Uint8Array[] {
  return Array.isArray(xs) && xs.every((x) => x instanceof Uint8Array && x.length === HASH_LENGTH);
}

export interface InclusionInput {
  leafIndex: number;
  treeSize: number;
  leaf: Uint8Array;   // the leaf HASH (leafHash(content)), never trusted from a proof
  path: Uint8Array[];
  root: Uint8Array;
}

/** RFC 9162 §2.1.3.2: does `path` prove `leaf` is at `leafIndex` in the tree
 *  of `treeSize` leaves whose root is `root`? */
export async function verifyInclusion(i: InclusionInput): Promise<boolean> {
  if (!i || !validSize(i.leafIndex) || !validSize(i.treeSize)) return false;
  if (i.leafIndex >= i.treeSize) return false;
  if (!(i.leaf instanceof Uint8Array) || i.leaf.length !== HASH_LENGTH) return false;
  if (!(i.root instanceof Uint8Array) || i.root.length !== HASH_LENGTH) return false;
  if (!validHashes(i.path)) return false;
  let fn = i.leafIndex;
  let sn = i.treeSize - 1;
  let r = i.leaf;
  for (const p of i.path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn !== 0 && fn % 2 === 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && bytesEqual(r, i.root);
}

export interface ConsistencyInput {
  first: number;
  second: number;
  firstRoot: Uint8Array;
  secondRoot: Uint8Array;
  proof: Uint8Array[];
}

/** RFC 9162 §2.1.4.2: does `proof` show the tree of `second` leaves (root
 *  `secondRoot`) extends the tree of `first` leaves (root `firstRoot`)?
 *  A tree of size 0 is consistent with everything (empty proof required). */
export async function verifyConsistency(c: ConsistencyInput): Promise<boolean> {
  if (!c || !validSize(c.first) || !validSize(c.second)) return false;
  if (c.second < c.first) return false;
  if (!validHashes(c.proof)) return false;
  if (c.first === 0) return c.proof.length === 0;
  if (!(c.firstRoot instanceof Uint8Array) || c.firstRoot.length !== HASH_LENGTH) return false;
  if (!(c.secondRoot instanceof Uint8Array) || c.secondRoot.length !== HASH_LENGTH) return false;
  if (c.first === c.second) return c.proof.length === 0 && bytesEqual(c.firstRoot, c.secondRoot);
  if (c.proof.length === 0) return false;

  // If first is an exact power of two, the first root is itself the first
  // node of the proof (RFC 9162 step 1).
  let odd = c.first;
  while (odd % 2 === 0) odd /= 2;
  const isPow2 = odd === 1;
  const proof = isPow2 ? [c.firstRoot, ...c.proof] : c.proof;

  let fn = c.first - 1;
  let sn = c.second - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = proof[0] as Uint8Array;
  let sr = proof[0] as Uint8Array;
  for (let k = 1; k < proof.length; k++) {
    const p = proof[k] as Uint8Array;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(p, fr);
      sr = await nodeHash(p, sr);
      if (fn % 2 === 0) {
        while (fn !== 0 && fn % 2 === 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      }
    } else {
      sr = await nodeHash(sr, p);
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && bytesEqual(fr, c.firstRoot) && bytesEqual(sr, c.secondRoot);
}
