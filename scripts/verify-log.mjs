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
//   node scripts/verify-log.mjs inclusion   <proof.json> [sth.json] --key <public_key_b64> --receipt <receipt.json>
//   node scripts/verify-log.mjs consistency <proof.json>
//   node scripts/verify-log.mjs sth         <sth.json> <public_key_b64>
//
// proof.json shapes are exactly what GET /v1/receipts/log/proof and
// /v1/receipts/log/consistency return (the `data` object).
//
// inclusion trusts nothing the proof carries: the STH (arg 2, else proof.sth)
// must verify under the pinned --key (never sth.signature.public_key) and match
// the proof's root_hash/tree_size, and the leaf is recomputed from the receipt
// bytes, leafHash(jcs(receipt)) — the receipt exactly as supplied, nothing
// stripped, matching the sequencer's `leaf = SHA-256(0x00 || JCS(receipt))`
// (verdict receipts are logged with their self-verification triple) — the proof's
// leaf_hash is ignored. Missing --key, --receipt or an STH exits 2.

import { createHash, verify as edVerify, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

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

// Own RFC 8785 canonicalization for the STH body and the receipt leaf (JSON
// subset: ES number/string serialization, which is what RFC 8785 specifies for
// the finite numbers and well-formed strings these documents carry). A lone
// surrogate is refused as the package's src/jcs.ts refuses it (2026-10-19):
// JSON.stringify would escape it to \uDxxx and this leaf would differ from
// every other canonicalizer's bytes for the same document.
export function jcs(v) {
  if (typeof v === 'string') {
    for (const ch of v) {
      const cp = ch.codePointAt(0);
      if (cp >= 0xd800 && cp <= 0xdfff) throw new Error('JCS: lone surrogate in string');
    }
  }
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${jcs(k)}:${jcs(v[k])}`).join(',')}}`;
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
const USAGE = 'usage: verify-log.mjs inclusion <proof.json> [sth.json] --key <b64> --receipt <receipt.json>'
  + ' | consistency <proof.json> | sth <sth.json> <public_key_b64>';

function main() {
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({
      options: { key: { type: 'string' }, receipt: { type: 'string' } },
      allowPositionals: true,
    }));
  } catch (e) { console.error(`${e.message}\n${USAGE}`); process.exit(2); }
  const [mode, ...args] = positionals;
  const load = (p) => JSON.parse(readFileSync(p, 'utf8'));
  const unwrap = (j) => (j && j.ok === true && j.data ? j.data : j);

  if (mode === 'inclusion') {
    const p = unwrap(load(args[0]));
    const sth = args[1] ? unwrap(load(args[1])) : p.sth;
    if (!values.key || !values.receipt || !sth) {
      console.error('inclusion requires --key <public_key_b64>, --receipt <receipt.json> and an STH (arg 2 or proof.sth)');
      process.exit(2);
    }
    // Accept a bare receipt, a { receipt }, or a /v1/verdict-style response.
    let receipt = unwrap(load(values.receipt));
    if (receipt.receipt) receipt = receipt.receipt;
    const okIncl = verifyInclusion({
      leafIndex: p.leaf_index, treeSize: p.tree_size,
      leaf: leafHash(Buffer.from(jcs(receipt))), path: p.audit_path.map(unhex), root: unhex(p.root_hash),
    });
    const okSig = verifySth(sth, values.key)
      && sth.root_hash === p.root_hash && sth.tree_size === p.tree_size;
    console.log(JSON.stringify({ inclusion: okIncl, sth_signature: okSig }));
    process.exit(okIncl && okSig ? 0 : 1);
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
  console.error(USAGE);
  process.exit(2);
}
if (import.meta.url === `file://${process.argv[1]}`) main();
