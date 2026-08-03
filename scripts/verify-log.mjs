#!/usr/bin/env node
// Moved here 2026-08-02 from tunnelmind-data-api/scripts/verify-log.mjs
// (research-house shift, part 2): the offline log verifier is part of the
// public verification kernel and lives in this repo alongside the receipt
// verifier. Byte-identical to the original at the time of the move.
//
// P72 Gate 2 — INDEPENDENT verifier for the TunnelMind receipt transparency
// log (RFC 6962 / RFC 9162 algorithms). By design this file imports ONLY
// node: builtins — zero TunnelMind library code, zero helpers shared with the
// sequencer (api/lib/receipt-log.js). The point is to catch a shared hashing
// bug, not to confirm the sequencer agrees with itself. Independence is
// asserted mechanically in api/lib/receipt-log.test.js.
//
// Usage:
//   node scripts/verify-log.mjs inclusion   <proof.json> [sth.json]
//   node scripts/verify-log.mjs consistency <proof.json>
//   node scripts/verify-log.mjs sth         <sth.json> <public_key_b64>
//
// proof.json shapes are exactly what GET /v1/receipts/log/proof and
// /v1/receipts/log/consistency return (the `data` object).

import { createHash, verify as edVerify, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

// ── primitives (deliberately re-implemented) ─────────────────────────────────
const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
const unhex = (s) => Buffer.from(String(s).replace(/^0x/, ''), 'hex');
const eq = (a, b) => a.length === b.length && a.equals(b);
const LEAF = Buffer.from([0x00]);
const NODE = Buffer.from([0x01]);

// Own RFC 8785 canonicalization for the STH body (JSON subset: no exotic
// numbers in an STH — tree_size is an integer, everything else strings).
export function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`;
}

/** RFC 6962 leaf hash of canonical content bytes. */
export function leafHash(contentBytes) {
  return sha256(LEAF, contentBytes);
}

/** RFC 9162 §2.1.3.2 — verify an inclusion proof. All hashes are Buffers. */
export function verifyInclusion({ leafIndex, treeSize, leaf, path, root }) {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return false;
  if (leafIndex < 0 || leafIndex >= treeSize) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = sha256(NODE, p, r);
      if ((fn & 1) === 0) {
        while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1; }
      }
    } else {
      r = sha256(NODE, r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eq(r, root);
}

/** RFC 9162 §2.1.4.2 — verify a consistency proof between two tree sizes. */
export function verifyConsistency({ first, second, firstRoot, secondRoot, proof }) {
  if (!Number.isInteger(first) || !Number.isInteger(second)) return false;
  if (first < 1 || second < first) return false;
  if (first === second) return proof.length === 0 && eq(firstRoot, secondRoot);
  if (proof.length === 0) return false;

  let fn = first - 1;
  let sn = second - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }

  let i = 0;
  let fr, sr;
  if (fn !== 0) { fr = sr = proof[i++]; }
  else { fr = sr = firstRoot; }

  for (; i < proof.length; i++) {
    const c = proof[i];
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = sha256(NODE, c, fr);
      sr = sha256(NODE, c, sr);
      while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1; }
    } else {
      sr = sha256(NODE, sr, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eq(fr, firstRoot) && eq(sr, secondRoot);
}

/** Verify an STH document's Ed25519 signature against a raw 32-byte b64 key. */
export function verifySth(sth, publicKeyB64) {
  const { signature, ...body } = sth;
  if (!signature || signature.algorithm !== 'Ed25519') return false;
  const raw = Buffer.from(publicKeyB64, 'base64');
  if (raw.length !== 32) return false;
  // Wrap the raw key in SPKI DER (RFC 8410 prefix) for node:crypto.
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return edVerify(null, Buffer.from(jcs(body)), key, Buffer.from(signature.value, 'base64'));
}

// ── CLI ──────────────────────────────────────────────────────────────────────
function main() {
  const [mode, ...args] = process.argv.slice(2);
  const load = (p) => JSON.parse(readFileSync(p, 'utf8'));
  const unwrap = (j) => (j && j.ok === true && j.data ? j.data : j);

  if (mode === 'inclusion') {
    const p = unwrap(load(args[0]));
    const okIncl = verifyInclusion({
      leafIndex: p.leaf_index, treeSize: p.tree_size,
      leaf: unhex(p.leaf_hash), path: p.audit_path.map(unhex), root: unhex(p.root_hash),
    });
    let okSig = null;
    const sth = args[1] ? unwrap(load(args[1])) : p.sth;
    if (sth && sth.signature?.public_key) okSig = verifySth(sth, sth.signature.public_key)
      && sth.root_hash === p.root_hash && sth.tree_size === p.tree_size;
    console.log(JSON.stringify({ inclusion: okIncl, sth_signature: okSig }));
    process.exit(okIncl && okSig !== false ? 0 : 1);
  }
  if (mode === 'consistency') {
    const p = unwrap(load(args[0]));
    const okc = verifyConsistency({
      first: p.first, second: p.second,
      firstRoot: unhex(p.first_root), secondRoot: unhex(p.second_root),
      proof: p.proof.map(unhex),
    });
    console.log(JSON.stringify({ consistency: okc }));
    process.exit(okc ? 0 : 1);
  }
  if (mode === 'sth') {
    const oks = verifySth(unwrap(load(args[0])), args[1]);
    console.log(JSON.stringify({ sth_signature: oks }));
    process.exit(oks ? 0 : 1);
  }
  console.error('usage: verify-log.mjs inclusion|consistency|sth <files…>');
  process.exit(2);
}
if (import.meta.url === `file://${process.argv[1]}`) main();
