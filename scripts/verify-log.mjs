#!/usr/bin/env node
// INDEPENDENT verifier for the TunnelMind receipt transparency log (RFC 6962
// / RFC 9162 inclusion + consistency proofs, Ed25519 STH signatures). By
// design this file imports ONLY node: builtins — zero TunnelMind library
// code, zero helpers shared with the sequencer (tunnelmind-data-api
// api/lib/receipt-log.js), whose test suite asserts that mechanically. The
// point is to catch a shared hashing bug, not to confirm the sequencer agrees
// with itself. jcs() is deliberately NOT the package canonicalizer (unlike
// scripts/verdict-lib/jcs.js, which re-exports it), so a shared JCS bug is
// caught; the re-implementation is pinned to the package's by
// test/vectors/jcs.json. Dialect: STH = Ed25519 over JCS(sth minus
// `signature`), standard base64; leaf = SHA-256(0x00 || JCS(receipt)).
// Trust: only the --key / public_key_b64 argument; never a key the STH or
// proof carries, never the proof's own leaf_hash. Every verifier returns
// false on malformed input (no throw); the CLI exits 1 on any failed check,
// 2 on bad usage.
//
// Usage:
//   node scripts/verify-log.mjs inclusion   <proof.json> [sth.json] (--key <public_key_b64> | --log-keys <doc.json> --receipt-key=<b64>) --receipt <receipt.json>
//   node scripts/verify-log.mjs consistency <proof.json> <older_sth.json> <newer_sth.json> (--key <public_key_b64> | --log-keys <doc.json> --receipt-key=<b64>)
//   node scripts/verify-log.mjs sth         <sth.json> <public_key_b64> [--receipt-key=<b64> [--allow-shared]]
//   node scripts/verify-log.mjs sth         <sth.json> --log-keys <doc.json> --receipt-key=<b64>
//   node scripts/verify-log.mjs handover    <doc.json> --receipt-key=<b64>
//
// Lineage: this file is the upstream. The Data API's vendored copy grew a
// local delta on 2026-11-10/11 (`sth --receipt-key/--allow-shared`,
// `sth --log-keys`, `handover`); that delta is carried here, with this file's
// stricter parts kept (standard base64 only, no throws, three-argument
// consistency). Re-vendor from here.
//
// Give --receipt-key as `--receipt-key=<b64>`: node's parseArgs refuses
// `--receipt-key -...` as ambiguous (exit 2), so a value starting with '-'
// only reaches this file's own checks in the '=' form.
//
// sth --receipt-key adds "log_key": "own" when the log key differs from the
// given receipt key, "shared_with_receipts" when it is the same key (compared
// as decoded bytes). Shared exits 1 unless --allow-shared. A --receipt-key
// that is not a standard-base64 32-byte key exits 2. Without --receipt-key
// the output is unchanged.
//
// Key document (sth --log-keys, handover): a document cannot authenticate
// itself, so --receipt-key is required and keys[0].public_key must equal that
// pin (first_key_not_pinned). Each key covers a tree-size range (from <= size
// <= until, null = open): the key named by signature.key_id must be in the
// document, sign the head, and cover its tree size; sth.log_id must be the
// document's; a head under a handed-over key must carry key_id in its signed
// body; a head at a cut-over size, under either key, must carry the hand-over
// root. Every entry after the first must carry a hand-over signed by the
// PREVIOUS key that names this entry. Both modes print {valid, ..., reason}.
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
//
// inclusion / consistency --log-keys: for a log whose signing key was handed
// over, give the key document instead of --key. Each head is then checked
// against the document exactly as `sth --log-keys` checks it (anchored on
// --receipt-key, key chosen by signature.key_id, tree size inside that key's
// range), so a consistency proof may run from a head under the first key to a
// head under the handed-over key. Nothing else changes: roots and sizes still
// come from the heads. Output gains "reason" (the head check's, or null).
// Exactly one of --key and --log-keys; both, neither, or --log-keys without
// --receipt-key exits 2.

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
// surrogate is refused as the package's src/jcs.ts refuses it: JSON.stringify
// would escape it to \uDxxx and this leaf would differ from every other
// canonicalizer's bytes for the same document.
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

// Standard base64 only: Buffer.from(s, 'base64') also takes the base64url
// alphabet and skips junk, so without this guard a signature the package's
// atob() refuses would verify here and the two verifiers would disagree.
const isB64 = (s) => typeof s === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(s);

/** Verify an STH document's Ed25519 signature against a raw 32-byte b64 key.
 *  False (never a throw) for a non-object STH, a non-Ed25519 or malformed
 *  signature, a non-base64 value or key, or a key that is not 32 bytes. */
export function verifySth(sth, publicKeyB64) {
  if (!sth || typeof sth !== 'object') return false;
  const { signature, ...body } = sth;
  if (!signature || signature.algorithm !== 'Ed25519') return false;
  if (!isB64(signature.value) || !isB64(publicKeyB64)) return false;
  const raw = Buffer.from(publicKeyB64, 'base64');
  if (raw.length !== 32) return false;
  // Wrap the raw key in SPKI DER (RFC 8410 prefix) for node:crypto.
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]);
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  return edVerify(null, Buffer.from(jcs(body)), key, Buffer.from(signature.value, 'base64'));
}

// ── key document — re-implemented, nothing imported ──────────────────────────
// checkLogKeys and checkSthKey are the Data API's functions: same reason
// strings, same order of checks (first failure wins). Two differences, both
// stricter: isB64 inside is32/sameKey, and no input makes them throw.
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string' && v.length > 0;
const isSize = (v) => Number.isSafeInteger(v) && v >= 0;
// isB64 first: Buffer.from(s, 'base64') also decodes base64url and skips junk,
// so without it a key the package's decoder refuses would count as 32 bytes
// (is32) or as equal to the pin (sameKey), and the two verifiers would
// disagree on one document. A non-string or empty pin equals nothing.
const is32 = (b64) => isStr(b64) && isB64(b64) && Buffer.from(b64, 'base64').length === 32;
const isHex32 = (v) => typeof v === 'string' && /^(0x)?[0-9a-f]{64}$/i.test(v); // Buffer hex parsing stops silently at a bad digit
const sameKey = (a, b) => isStr(a) && isStr(b) && isB64(a) && isB64(b) && Buffer.from(a, 'base64').equals(Buffer.from(b, 'base64'));
// tm-log-YYYY-MM. Same pattern as the sequencer's, repeated here so the
// verifier imports nothing.
const LOG_KEY_ID_RE = /^tm-log-[0-9]{4}-(0[1-9]|1[0-2])$/;
// verifySth returns false on malformed input, but jcs() throws on a lone
// surrogate anywhere in the signed body; a reason string must come back.
const sigOk = (doc, pubB64) => { try { return verifySth(doc, pubB64); } catch { return false; } };

/** Why a key document is invalid (a short fixed string), or null when valid.
 *  Never throws. */
export function checkLogKeys(doc) {
  if (!isObj(doc) || !isStr(doc.log_id) || !Array.isArray(doc.keys) || doc.keys.length === 0) return 'bad_doc';
  const ids = new Set();
  const handoverTo = new Set();
  for (let i = 0; i < doc.keys.length; i++) {
    const k = doc.keys[i];
    const prev = doc.keys[i - 1];
    if (!isObj(k) || !isStr(k.key_id) || !is32(k.public_key)) return 'bad_entry';
    if (i > 0 && !LOG_KEY_ID_RE.test(k.key_id)) return 'bad_key_id'; // keys[0] is the receipt key, own id
    if (!isSize(k.from_tree_size) || k.from_tree_size !== (i === 0 ? 0 : prev.until_tree_size)) return 'bad_range';
    // until > from: a zero-width range lets two hand-overs at one size carry two roots.
    if (k.until_tree_size === null ? i !== doc.keys.length - 1 : !(isSize(k.until_tree_size) && k.until_tree_size > k.from_tree_size)) return 'bad_range';
    const h = k.handover;
    // A later key without a hand-over is one the old key never endorsed.
    if (i > 0 && h === undefined) return 'handover_missing';
    if (h !== undefined) {
      if (i === 0) return 'handover_on_first_entry';
      if (!isObj(h) || h.type !== 'tunnelmind.log-key-handover/v1' || !isHex32(h.root_hash)) return 'bad_handover';
      if (handoverTo.has(h.to_key_id)) return 'handover_replay';
      handoverTo.add(h.to_key_id);
      if (h.log_id !== doc.log_id) return 'handover_log_id';
      if (h.from_key_id !== prev.key_id) return 'handover_from_key';
      if (h.to_key_id !== k.key_id || !sameKey(h.to_public_key, k.public_key)) return 'handover_to_key';
      if (h.tree_size !== k.from_tree_size) return 'handover_tree_size';
      if (!sigOk(h, prev.public_key)) return 'handover_signature';
    }
    // Checked after the hand-over so a replayed hand-over reports as one.
    if (ids.has(k.key_id)) return 'duplicate_key_id';
    ids.add(k.key_id);
  }
  return null;
}

/** Why a head is invalid under the key document, or null when valid. Never
 *  throws. `receiptKeyB64` is the pinned trust anchor: the document's first
 *  key must be it, so a missing or malformed pin fails closed. */
export function checkSthKey(sth, doc, receiptKeyB64) {
  if (checkLogKeys(doc) !== null) return 'invalid_key_doc';
  if (!sameKey(doc.keys[0].public_key, receiptKeyB64)) return 'first_key_not_pinned';
  const sig = isObj(sth) ? sth.signature : null;
  if (!isObj(sig) || !isStr(sig.key_id)) return 'no_signature';
  if (sth.log_id !== doc.log_id) return 'log_id_mismatch';
  if ('key_id' in sth && sth.key_id !== sig.key_id) return 'key_id_mismatch';
  const idx = doc.keys.findIndex((k) => k.key_id === sig.key_id);
  if (idx < 0) return 'unknown_key_id';
  const e = doc.keys[idx];
  // Own-key heads sign their key id; only first-entry (shared) heads may lack it.
  if (e.handover && !('key_id' in sth)) return 'key_id_missing';
  if ('public_key' in sig && !sameKey(sig.public_key, e.public_key)) return 'public_key_mismatch';
  if (!sigOk(sth, e.public_key)) return 'bad_signature';
  const n = sth.tree_size;
  if (!isSize(n) || n < e.from_tree_size || (e.until_tree_size !== null && n > e.until_tree_size)) return 'tree_size_out_of_range';
  // At the cut-over size both keys must sign the very tree the old key handed over.
  const rootIs = (h) => isHex32(sth.root_hash) && eq(unhex(sth.root_hash), unhex(h.root_hash));
  if (e.handover && n === e.from_tree_size && !rootIs(e.handover)) return 'root_mismatch';
  const next = doc.keys[idx + 1];
  if (next?.handover && n === e.until_tree_size && !rootIs(next.handover)) return 'root_mismatch';
  return null;
}

// ── CLI ──────────────────────────────────────────────────────────────────────
const USAGE = 'usage: verify-log.mjs inclusion <proof.json> [sth.json] (--key <b64> | --log-keys <doc.json> --receipt-key=<b64>) --receipt <receipt.json>'
  + ' | consistency <proof.json> <older_sth.json> <newer_sth.json> (--key <b64> | --log-keys <doc.json> --receipt-key=<b64>)'
  + ' | sth <sth.json> <public_key_b64> [--receipt-key=<b64> [--allow-shared]]'
  + ' | sth <sth.json> --log-keys <doc.json> --receipt-key=<b64> | handover <doc.json> --receipt-key=<b64>'
  + " (use the '=' form: a key starting with '-' is refused otherwise)";

function main() {
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({
      options: {
        key: { type: 'string' }, receipt: { type: 'string' },
        'receipt-key': { type: 'string' }, 'allow-shared': { type: 'boolean' },
        'log-keys': { type: 'string' },
      },
      allowPositionals: true,
    }));
  } catch (e) { console.error(`${e.message}\n${USAGE}`); process.exit(2); }
  const [mode, ...args] = positionals;
  const load = (p) => JSON.parse(readFileSync(p, 'utf8'));
  const unwrap = (j) => (j && j.ok === true && j.data ? j.data : j);
  // inclusion / consistency take exactly one trust anchor: --key (one pinned
  // log key), or --log-keys anchored on --receipt-key exactly as `sth
  // --log-keys` (no pin, no verification: the document alone proves nothing).
  const docMode = values['log-keys'] !== undefined;
  const anchorOk = docMode ? values.key === undefined && !!values['receipt-key'] : !!values.key;
  const ANCHOR = '--key <public_key_b64> or --log-keys <doc.json> --receipt-key=<b64> (not both)';

  if (mode === 'inclusion') {
    const p = unwrap(load(args[0]));
    const sth = args[1] ? unwrap(load(args[1])) : p.sth;
    if (!anchorOk || !values.receipt || !sth) {
      console.error(`inclusion requires ${ANCHOR}, --receipt <receipt.json> and an STH (arg 2 or proof.sth)\n${USAGE}`);
      process.exit(2);
    }
    // Accept a bare receipt, a { receipt }, or a /v1/verdict-style response.
    let receipt = unwrap(load(values.receipt));
    if (receipt.receipt) receipt = receipt.receipt;
    const okIncl = verifyInclusion({
      leafIndex: p.leaf_index, treeSize: p.tree_size,
      leaf: leafHash(Buffer.from(jcs(receipt))), path: p.audit_path.map(unhex), root: unhex(p.root_hash),
    });
    // Only the head-signature step differs by mode; the head must match the proof either way.
    const reason = docMode ? checkSthKey(sth, unwrap(load(values['log-keys'])), values['receipt-key']) : null;
    const okSig = (docMode ? reason === null : verifySth(sth, values.key))
      && sth.root_hash === p.root_hash && sth.tree_size === p.tree_size;
    console.log(JSON.stringify({ inclusion: okIncl, sth_signature: okSig, ...(docMode && { reason }) }));
    process.exit(okIncl && okSig ? 0 : 1);
  }
  if (mode === 'consistency') {
    // The roots come from the two STHs, each verified under the pinned --key
    // (or, with --log-keys, each on its own against the key document: the
    // older may be under the first key, the newer under the handed-over one);
    // the proof's own first_root/second_root are only checked against them.
    // A proof alone is self-consistent by construction and proves nothing.
    if (!anchorOk || args.length !== 3) {
      console.error(`consistency requires <proof.json> <older_sth.json> <newer_sth.json> and ${ANCHOR}\n${USAGE}`);
      process.exit(2);
    }
    const p = unwrap(load(args[0]));
    const older = unwrap(load(args[1]));
    const newer = unwrap(load(args[2]));
    let reason = null;
    if (docMode) {
      const doc = unwrap(load(values['log-keys']));
      reason = checkSthKey(older, doc, values['receipt-key']) ?? checkSthKey(newer, doc, values['receipt-key']);
    }
    const okSigs = docMode ? reason === null : verifySth(older, values.key) && verifySth(newer, values.key);
    const rootsAgree = (p.first_root === undefined || String(p.first_root).replace(/^0x/, '') === String(older.root_hash).replace(/^0x/, ''))
      && (p.second_root === undefined || String(p.second_root).replace(/^0x/, '') === String(newer.root_hash).replace(/^0x/, ''));
    const sizesAgree = p.first === older.tree_size && p.second === newer.tree_size;
    const okc = okSigs && rootsAgree && sizesAgree && verifyConsistency({
      first: older.tree_size, second: newer.tree_size,
      firstRoot: unhex(older.root_hash), secondRoot: unhex(newer.root_hash),
      proof: (p.proof ?? []).map(unhex),
    });
    console.log(JSON.stringify({ consistency: okc, sth_signatures: okSigs, ...(docMode && { reason }) }));
    process.exit(okc ? 0 : 1);
  }
  if (mode === 'sth' && values['log-keys'] !== undefined) {
    // No pin, no verification: the document alone proves nothing.
    if (!args[0] || !values['receipt-key']) { console.error(`sth --log-keys requires <sth.json> and --receipt-key=<b64>\n${USAGE}`); process.exit(2); }
    const sth = unwrap(load(args[0]));
    const reason = checkSthKey(sth, unwrap(load(values['log-keys'])), values['receipt-key']);
    const keyId = isStr(sth?.signature?.key_id) ? sth.signature.key_id : null;
    console.log(JSON.stringify({ valid: reason === null, key_id: keyId, reason }));
    process.exit(reason === null ? 0 : 1);
  }
  if (mode === 'handover') {
    // Same anchor as sth --log-keys: a document cannot vouch for itself.
    if (!args[0] || !values['receipt-key']) { console.error(`handover requires <doc.json> and --receipt-key=<b64>\n${USAGE}`); process.exit(2); }
    const doc = unwrap(load(args[0]));
    const reason = checkLogKeys(doc) ?? (sameKey(doc.keys[0].public_key, values['receipt-key']) ? null : 'first_key_not_pinned');
    console.log(JSON.stringify({ valid: reason === null, reason }));
    process.exit(reason === null ? 0 : 1);
  }
  if (mode === 'sth') {
    const oks = verifySth(unwrap(load(args[0])), args[1]);
    if (values['receipt-key'] === undefined) {
      console.log(JSON.stringify({ sth_signature: oks }));
      process.exit(oks ? 0 : 1);
    }
    // sameKey refuses anything but standard base64, so a receipt key it cannot
    // decode (base64url, empty) would compare unequal and report "own" for
    // what may be the same key. Refuse it as bad usage instead.
    if (!is32(values['receipt-key'])) { console.error(`--receipt-key must be a standard-base64 32-byte key\n${USAGE}`); process.exit(2); }
    // Compare decoded bytes, not strings.
    const shared = sameKey(args[1], values['receipt-key']);
    console.log(JSON.stringify({ sth_signature: oks, log_key: shared ? 'shared_with_receipts' : 'own' }));
    process.exit(oks && (!shared || values['allow-shared']) ? 0 : 1);
  }
  console.error(USAGE);
  process.exit(2);
}
if (import.meta.url === `file://${process.argv[1]}`) main();
