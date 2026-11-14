// Receipt transparency-log verification: signed tree heads (STHs), receipt
// inclusion, STH-to-STH consistency, and a LogMonitor that remembers the
// last STH it saw and refuses any advance it cannot prove append-only.
//
// Dialect (as served by data.tunnelmind.ai/v1/receipts/log/{sth,proof,consistency}
// and verified by scripts/verify-log.mjs):
//   STH   = { tree_size, root_hash, timestamp, ...,
//             signature: { algorithm: 'Ed25519', value, key_id?, public_key? } }
//           signed bytes = JCS(sth minus `signature`), standard base64.
//   leaf  = SHA-256(0x00 || JCS(receipt exactly as supplied)).
//   proof = { leaf_index, tree_size, audit_path[hex], root_hash, leaf_hash?, sth? }
//   consistency = { first, second, proof[hex], first_root?, second_root? }
// `log_id` and `signature.key_id` on the STH are OPTIONAL in the dialect:
// when present they are bound (key_id must name a pinned log key; log_id
// must match that key's log_id). The live log (2026-11-07) emits both
// (log_id tunnelmind-receipts-log-v1, key_id tm-receipt-2026-05), so
// callers should set `requireKeyId` and `logId`.
//
// Trust: ONLY the caller's pinned `logKeys`. Never a key the STH, proof or
// receipt carries, never the proof's own leaf_hash or roots, and the
// receipt-signing bundle is never consulted on its own.
// Log-key mode (logKeyMode), decided by the pinned `logKeys` against the
// receipt-signing keys (`SthOptions.receiptKeys`, default the pinned bundle):
//   shared_with_receipts  every usable log key is a receipt key. This is the
//       live log today (2026-11): it signs STHs with tm-receipt-2026-05, so
//       issuer and log witness are one key and inclusion proves the receipt
//       is in the issuer's own log, not that a second party saw it.
//   separate  at least one log key is not a receipt key. Then a log key
//       equal to a receipt key is refused at load, so a tree head signed by
//       the receipt-issuing key can never verify. A mixed set is refused.
// Results report the mode as `log_key`.
// Key windows: a log key's status and [created_at, rotation_after] window
// are checked against the STH's own timestamp (keys.ts keyUsableAt), so a
// key past rotation stops verifying new heads. The timestamp is the log's
// claim; a stolen rotated key can backdate it, exactly as for receipts.
// Key document (checkLogKeyDoc): the log's published list of keys by tree
// size, each later key endorsed by a hand-over the previous key signed, the
// first key anchored on a receipt key.
// Key-document mode: verifySth(sth, doc) with such a document (PINNED_LOG_KEYS,
// or the served file) instead of a key array applies ADR-047 §7 as the CLI's
// checkSthKey does. The trust anchor is the receipt key, not the document:
// keys[0] must be a receipt key and every later key hangs off it by signed
// hand-overs. Each key signs only inside its tree-size range, which replaces
// the time window (no keyUsableAt here), and the head must name its key.
// Fail closed: every function returns errors, never throws on bad input.

import { canonicalizeBytes, type JsonValue } from './jcs.js';
import { keyUsableAt, type SigningKeyEntry } from './keys.js';
import { PINNED_KEY_BUNDLE } from './pinned-keys.js';
import { b64ToBytes, signatureBytes, toAB } from './bytes.js';
import {
  bytesEqual,
  leafHash,
  parseHash,
  verifyConsistency,
  verifyInclusion,
} from './merkle.js';

const subtle = globalThis.crypto.subtle;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface SthSignature {
  algorithm: 'Ed25519';
  value: string;
  key_id?: string;
  public_key?: string; // carried for information only; never trusted
}

export interface SignedTreeHead {
  tree_size: number;
  root_hash: string;
  timestamp?: string;
  log_id?: string;
  signature: SthSignature;
  [k: string]: unknown;
}

export interface InclusionProof {
  leaf_index: number;
  tree_size: number;
  audit_path: string[];
  root_hash: string;
  leaf_hash?: string; // ignored: the leaf is recomputed from the receipt
  sth?: SignedTreeHead;
}

export interface ConsistencyProof {
  first: number;
  second: number;
  proof: string[];
  first_root?: string;  // if present must equal the older STH's root
  second_root?: string; // if present must equal the newer STH's root
}

/** A pinned log signing key. Same shape as a receipt-bundle entry, plus the
 *  log it signs for. Entries with status `revoked` are never used. */
export interface LogKeyEntry extends SigningKeyEntry {
  log_id?: string;
}

/** The previous key's signed statement that the log moves to `to_key_id` at
 *  `tree_size` under `root_hash`. Signed bytes = JCS(hand-over minus `signature`). */
export interface LogKeyHandover {
  type: 'tunnelmind.log-key-handover/v1';
  log_id: string;
  from_key_id: string;
  to_key_id: string;
  to_public_key: string;
  tree_size: number;
  root_hash: string;
  signature: SthSignature;
  [k: string]: unknown;
}

/** One key of a key document: it signs heads of tree sizes
 *  [from_tree_size, until_tree_size], open-ended when `until_tree_size` is null. */
export interface LogKeyDocEntry {
  key_id: string;
  public_key: string;
  from_tree_size: number;
  until_tree_size: number | null;
  shared_with_receipts?: boolean;
  handover?: LogKeyHandover; // required on every entry but the first
  [k: string]: unknown;
}

/** The log's key document (key per tree size). Validate with checkLogKeyDoc. */
export interface LogKeyDoc {
  log_id: string;
  keys: LogKeyDocEntry[];
  [k: string]: unknown;
}

export interface SthOptions {
  /** Refuse an STH whose signature does not name a key_id. */
  requireKeyId?: boolean;
  /** Expected log; an STH or key bound to another log_id is refused. */
  logId?: string;
  /** The receipt-signing keys, to tell a shared log key from a separate one
   *  (see header). Default: the pinned receipt bundle's keys. */
  receiptKeys?: SigningKeyEntry[];
}

export type LogKeyMode = 'shared_with_receipts' | 'separate';

export interface SthResult {
  valid: boolean;
  errors: string[];
  /** Set once the pinned log keys were evaluated (any usable one). */
  log_key?: LogKeyMode;
  /** Key-document mode only: why the head was refused, the CLI's fixed string. */
  reason?: string;
  key_id?: string;
  log_id?: string;
  tree_size?: number;
}

export type LogStatus = 'included' | 'failed' | 'not_checked';

export interface InclusionResult {
  status: LogStatus;
  errors: string[];
  tree_size?: number;
  leaf_index?: number;
  log_key_id?: string;
  log_key?: LogKeyMode;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Same base64 rules as receipt signatures (bytes.ts): the pinned public key
 *  decodes as standard base64, the signature value must be canonical. */
async function ed25519Verify(publicKeyB64: string, sigB64: unknown, data: Uint8Array): Promise<boolean> {
  try {
    if (typeof sigB64 !== 'string') return false;
    const pub = b64ToBytes(publicKeyB64);
    const sig = signatureBytes(sigB64);
    if (pub.length !== 32 || sig.length !== 64) return false;
    const key = await subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
    return await subtle.verify('Ed25519', key, sig, toAB(data));
  } catch {
    return false;
  }
}

function usable(k: LogKeyEntry | null | undefined): k is LogKeyEntry {
  return !!k && typeof k.public_key === 'string' && k.status !== 'revoked'
    && (k.algorithm === undefined || k.algorithm === 'Ed25519');
}

/** Shared or separate log keys (see header), and in separate mode the error
 *  for a log key that is also a receipt key. Keys compare by public key
 *  bytes, so a re-spelled base64 of a receipt key is still caught. No usable
 *  log key → no mode (verifySth reports that). */
function logKeyMode(
  logKeys: LogKeyEntry[] | undefined,
  receiptKeys: SigningKeyEntry[] | undefined,
): { mode?: LogKeyMode; error?: string } {
  const keys = Array.isArray(logKeys) ? logKeys.filter(usable) : [];
  if (keys.length === 0) return {};
  const norm = (b64: string) => { try { return b64ToBytes(b64).join(','); } catch { return b64; } };
  const rks = Array.isArray(receiptKeys) ? receiptKeys : PINNED_KEY_BUNDLE.keys;
  const receipt = new Set(rks.flatMap((k) => (typeof k?.public_key === 'string' ? [norm(k.public_key)] : [])));
  const isReceiptKey = (k: LogKeyEntry) => receipt.has(norm(k.public_key));
  if (keys.every(isReceiptKey)) return { mode: 'shared_with_receipts' };
  const clash = keys.find(isReceiptKey);
  return clash
    ? { mode: 'separate', error: `log key ${clash.key_id} is also a receipt-signing key` }
    : { mode: 'separate' };
}

function isSize(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
}

// ── Key document ──────────────────────────────────────────────────────────────

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
// 32-byte hex, optional 0x: the CLI's pattern, kept as a pattern so both
// verifiers accept the very same spellings.
const isHex32 = (v: unknown): boolean => typeof v === 'string' && /^(0x)?[0-9a-f]{64}$/i.test(v);
// tm-log-YYYY-MM, the id every key after the first must carry.
const LOG_KEY_ID_RE = /^tm-log-[0-9]{4}-(0[1-9]|1[0-2])$/;

/** A key string → its bytes, or null. Standard base64 alphabet only: atob()
 *  alone forgives ASCII whitespace, which the CLI refuses. Padding is dropped
 *  before decoding because the CLI's decoder ignores how many `=` there are. */
function keyBytes(v: unknown): Uint8Array | null {
  if (!isStr(v) || !/^[A-Za-z0-9+/]*={0,2}$/.test(v)) return null;
  try { return b64ToBytes(v.replace(/=+$/, '')); } catch { return null; }
}
const key32 = (v: unknown): Uint8Array | null => {
  const b = keyBytes(v);
  return b && b.length === 32 ? b : null;
};

/** Why a key document is invalid (a short fixed string), or null when valid.
 *  Same reasons in the same order as checkLogKeys in scripts/verify-log.mjs
 *  (first failure wins), then the anchor the CLI applies per head: the first
 *  key must be, byte for byte, a non-revoked receipt key (`receiptKeys`,
 *  default the pinned bundle's), else `first_key_not_pinned`. Without the
 *  anchor anyone could publish a self-consistent chain of hand-overs.
 *  Resolves on any input; never throws or rejects. */
export async function checkLogKeyDoc(doc: unknown, receiptKeys?: SigningKeyEntry[]): Promise<string | null> {
  if (!isObj(doc) || !isStr(doc.log_id) || !Array.isArray(doc.keys) || doc.keys.length === 0) return 'bad_doc';
  const keys = doc.keys as unknown[];
  const ids = new Set<string>();
  const handoverTo = new Set<unknown>();
  let firstKey: Uint8Array | null = null;
  let prev: Obj | undefined;      // the previous entry, already checked
  let prevKey: Uint8Array | null = null;
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (!isObj(k) || !isStr(k.key_id)) return 'bad_entry';
    const pub = key32(k.public_key);
    if (!pub) return 'bad_entry';
    if (i === 0) firstKey = pub;
    if (i > 0 && !LOG_KEY_ID_RE.test(k.key_id)) return 'bad_key_id'; // keys[0] is the receipt key, own id
    if (!isSize(k.from_tree_size) || k.from_tree_size !== (prev ? prev.until_tree_size : 0)) return 'bad_range';
    // until > from: a zero-width range lets two hand-overs at one size carry two roots.
    if (k.until_tree_size === null
      ? i !== keys.length - 1
      : !(isSize(k.until_tree_size) && k.until_tree_size > k.from_tree_size)) return 'bad_range';
    const h = k.handover;
    // A later key without a hand-over is one the old key never endorsed.
    if (prev && h === undefined) return 'handover_missing';
    if (h !== undefined) {
      if (!prev || !prevKey) return 'handover_on_first_entry';
      if (!isObj(h) || h.type !== 'tunnelmind.log-key-handover/v1' || !isHex32(h.root_hash)) return 'bad_handover';
      if (handoverTo.has(h.to_key_id)) return 'handover_replay';
      handoverTo.add(h.to_key_id);
      if (h.log_id !== doc.log_id) return 'handover_log_id';
      if (h.from_key_id !== prev.key_id) return 'handover_from_key';
      const to = keyBytes(h.to_public_key);
      if (h.to_key_id !== k.key_id || !to || !bytesEqual(to, pub)) return 'handover_to_key';
      if (h.tree_size !== k.from_tree_size) return 'handover_tree_size';
      const { signature: sig, ...body } = h;
      if (!isObj(sig) || sig.algorithm !== 'Ed25519') return 'handover_signature';
      let signed: Uint8Array;
      // canonicalizeBytes throws on a lone surrogate anywhere in the body.
      try { signed = canonicalizeBytes(body as JsonValue); } catch { return 'handover_signature'; }
      // The key goes in re-encoded from its bytes, so a spelling accepted
      // above cannot fail ed25519Verify's own decode.
      if (!(await ed25519Verify(btoa(String.fromCharCode(...prevKey)), sig.value, signed))) return 'handover_signature';
    }
    // Checked after the hand-over so a replayed hand-over reports as one.
    if (ids.has(k.key_id)) return 'duplicate_key_id';
    ids.add(k.key_id);
    prev = k;
    prevKey = pub;
  }
  const rks: unknown[] = Array.isArray(receiptKeys) ? receiptKeys : PINNED_KEY_BUNDLE.keys;
  const pinned = rks.some((r) => {
    if (!isObj(r) || r.status === 'revoked') return false;
    const b = key32(r.public_key);
    return !!b && !!firstKey && bytesEqual(b, firstKey);
  });
  return pinned ? null : 'first_key_not_pinned';
}

// ── Signed tree heads ─────────────────────────────────────────────────────────

/** verifySth with a key document: the same checks in the same order as
 *  checkSthKey in scripts/verify-log.mjs (first failure wins), reported as
 *  `reason`. The head must name its key (`signature.key_id`); no other key is
 *  ever tried. `log_key` says which kind of entry that key is. Never throws. */
// A type guard, so that past the early return in verifySth `logKeys` is the
// key array again and the array-mode code compiles untouched.
const isKeyDoc = (v: unknown): v is LogKeyDoc => isObj(v) && Array.isArray(v.keys);

async function verifySthDoc(sth: unknown, doc: LogKeyDoc, opts: SthOptions): Promise<SthResult> {
  const out: SthResult = { valid: false, errors: [] };
  const refuse = (reason: string): SthResult => {
    out.reason = reason;
    out.errors.push(reason);
    return out;
  };
  // The document first, anchored on the receipt key: nothing in an
  // unanchored or malformed document is used to judge a head.
  const docReason = await checkLogKeyDoc(doc, opts.receiptKeys);
  if (docReason !== null) return refuse(docReason === 'first_key_not_pinned' ? docReason : 'invalid_key_doc');
  const keys = doc.keys;

  const sig = isObj(sth) ? sth.signature : null;
  if (!isObj(sth) || !isObj(sig) || !isStr(sig.key_id)) return refuse('no_signature');
  // opts.logId has no CLI counterpart: a document for another log than the
  // caller expects is refused here too (fail closed).
  if (sth.log_id !== doc.log_id || (opts.logId && doc.log_id !== opts.logId)) return refuse('log_id_mismatch');
  if ('key_id' in sth && sth.key_id !== sig.key_id) return refuse('key_id_mismatch');
  const idx = keys.findIndex((k) => k.key_id === sig.key_id);
  const e = keys[idx];
  if (!e) return refuse('unknown_key_id');
  out.log_key = e.handover ? 'separate' : 'shared_with_receipts';
  // Own-key heads sign their key id; only first-entry (shared) heads may lack it.
  if (e.handover && !('key_id' in sth)) return refuse('key_id_missing');
  const pub = keyBytes(e.public_key) as Uint8Array; // decodes: checkLogKeyDoc passed
  if ('public_key' in sig) {
    const carried = keyBytes(sig.public_key);
    if (!carried || !bytesEqual(carried, pub)) return refuse('public_key_mismatch');
  }
  if (sig.algorithm !== 'Ed25519') return refuse('bad_signature');
  const { signature: _sig, ...body } = sth;
  void _sig;
  let signed: Uint8Array;
  try { signed = canonicalizeBytes(body as JsonValue); } catch { return refuse('bad_signature'); }
  // Canonical base64 signatures only (ed25519Verify); the CLI also takes
  // unpadded ones. The key goes in re-encoded from its bytes, as in checkLogKeyDoc.
  if (!(await ed25519Verify(btoa(String.fromCharCode(...pub)), sig.value, signed))) return refuse('bad_signature');
  const n = sth.tree_size;
  if (!isSize(n) || n < e.from_tree_size || (e.until_tree_size !== null && n > e.until_tree_size)) {
    return refuse('tree_size_out_of_range');
  }
  // At the cut-over size both keys must sign the very tree the old key handed over.
  const rootIs = (h: LogKeyHandover): boolean => {
    const a = isHex32(sth.root_hash) ? parseHash(sth.root_hash) : null;
    const b = parseHash(h.root_hash);
    return !!a && !!b && bytesEqual(a, b);
  };
  if (e.handover && n === e.from_tree_size && !rootIs(e.handover)) return refuse('root_mismatch');
  const next = keys[idx + 1];
  if (next?.handover && n === e.until_tree_size && !rootIs(next.handover)) return refuse('root_mismatch');

  out.valid = true;
  out.key_id = e.key_id;
  out.log_id = doc.log_id;
  out.tree_size = n;
  return out;
}

/** Verify an STH's Ed25519 signature against the pinned `logKeys` only.
 *  If the STH names `signature.key_id`, only that pinned key is tried;
 *  otherwise (legacy dialect, unless `requireKeyId`) each usable pinned key
 *  is tried. A key or STH bound to a different log_id than expected fails.
 *
 *  `logKeys` may instead be a key document (`LogKeyDoc`, e.g. PINNED_LOG_KEYS):
 *  then the ADR-047 §7 rules apply (see verifySthDoc and the header). The
 *  head must name its key, the key must cover the head's tree size, and a
 *  refusal carries the CLI's fixed string as `reason`. `requireKeyId` is
 *  moot in that mode (always required) and no time window is applied. */
export async function verifySth(
  sth: unknown,
  logKeys: LogKeyEntry[] | LogKeyDoc | undefined,
  opts: SthOptions = {},
): Promise<SthResult> {
  if (isKeyDoc(logKeys)) return verifySthDoc(sth, logKeys, opts);
  const errors: string[] = [];
  const out: SthResult = { valid: false, errors };
  // Key load first: a mixed log-key set is refused before the STH is read.
  const km = logKeyMode(logKeys, opts.receiptKeys);
  if (km.mode) out.log_key = km.mode;
  if (km.error) {
    errors.push(km.error);
    return out;
  }
  if (!sth || typeof sth !== 'object' || Array.isArray(sth)) {
    errors.push('sth must be an object');
    return out;
  }
  const s = sth as SignedTreeHead;
  if (!Array.isArray(logKeys) || logKeys.filter(usable).length === 0) {
    errors.push('no pinned log key: pass logKeys (the receipt-signing bundle is never used for the log)');
    return out;
  }
  if (!isSize(s.tree_size)) errors.push(`sth.tree_size: not a non-negative integer: ${String(s.tree_size)}`);
  if (!parseHash(s.root_hash)) errors.push('sth.root_hash: not a 32-byte hex hash');
  const sig = s.signature;
  if (!sig || typeof sig !== 'object' || sig.algorithm !== 'Ed25519') {
    errors.push(`sth.signature.algorithm: expected Ed25519, got ${String(sig?.algorithm)}`);
    return out;
  }
  if (sig.key_id !== undefined && (typeof sig.key_id !== 'string' || sig.key_id === '')) {
    errors.push('sth.signature.key_id: must be a non-empty string when present');
    return out;
  }
  if (opts.requireKeyId && !sig.key_id) {
    errors.push('sth.signature.key_id: required (requireKeyId)');
    return out;
  }
  if (s.log_id !== undefined && typeof s.log_id !== 'string') {
    errors.push('sth.log_id: must be a string when present');
    return out;
  }
  if (opts.logId && s.log_id && s.log_id !== opts.logId) {
    errors.push(`sth.log_id ${s.log_id} is not the expected log ${opts.logId}`);
    return out;
  }

  let candidates = logKeys.filter(usable);
  if (sig.key_id) candidates = candidates.filter((k) => k.key_id === sig.key_id);
  const wantLog = s.log_id ?? opts.logId;
  if (wantLog) candidates = candidates.filter((k) => !k.log_id || k.log_id === wantLog);
  // Status and validity window, against the STH's timestamp (see header).
  const tsMs = typeof s.timestamp === 'string' ? Date.parse(s.timestamp) : NaN;
  const windowReasons: string[] = [];
  candidates = candidates.filter((k) => {
    const why = keyUsableAt(k, tsMs, 'sth');
    if (why) windowReasons.push(why);
    return why === null;
  });
  if (candidates.length === 0) {
    errors.push(sig.key_id
      ? `sth.signature.key_id ${sig.key_id} is not a usable pinned log key${wantLog ? ` for log ${wantLog}` : ''}`
      : `no usable pinned log key${wantLog ? ` for log ${wantLog}` : ''}`);
    errors.push(...windowReasons);
    return out;
  }

  const { signature: _sig, ...body } = s;
  void _sig;
  let bytes: Uint8Array;
  try {
    bytes = canonicalizeBytes(body as unknown as JsonValue);
  } catch (e) {
    errors.push(`sth canonicalization failed: ${(e as Error).message}`);
    return out;
  }
  let signer: LogKeyEntry | undefined;
  for (const k of candidates) {
    if (await ed25519Verify(k.public_key, sig.value, bytes)) { signer = k; break; }
  }
  if (!signer) {
    errors.push('sth signature did not verify under any pinned log key');
    return out;
  }
  out.key_id = signer.key_id;
  out.log_id = s.log_id ?? signer.log_id;
  out.tree_size = s.tree_size;
  out.valid = errors.length === 0;
  return out;
}

// ── Inclusion ─────────────────────────────────────────────────────────────────

/** The log leaf hash of a receipt: SHA-256(0x00 || JCS(receipt as supplied)).
 *  Nothing is stripped (verdict receipts are logged with self_verification). */
export async function receiptLeafHash(receipt: unknown): Promise<Uint8Array> {
  return leafHash(canonicalizeBytes(receipt as JsonValue));
}

/** Prove `receipt` is in the log: the STH (argument, else proof.sth) must
 *  verify under a pinned log key and match the proof's root_hash and
 *  tree_size, and the audit path must lead from the receipt's recomputed
 *  leaf to that root. */
export async function verifyReceiptInclusion(
  receipt: unknown,
  proof: unknown,
  sth: unknown,
  logKeys: LogKeyEntry[] | undefined,
  opts: SthOptions = {},
): Promise<InclusionResult> {
  const errors: string[] = [];
  const out: InclusionResult = { status: 'failed', errors };
  const km = logKeyMode(logKeys, opts.receiptKeys);
  if (km.mode) out.log_key = km.mode;
  if (km.error) {
    errors.push(km.error);
    return out;
  }
  if (!proof || typeof proof !== 'object') {
    errors.push('inclusion proof must be an object');
    return out;
  }
  const p = proof as InclusionProof;
  const head = sth ?? p.sth;
  if (!head) {
    errors.push('no signed tree head: pass one or include proof.sth');
    return out;
  }
  const sr = await verifySth(head, logKeys, opts);
  if (!sr.valid) {
    errors.push(...sr.errors.map((e) => `sth: ${e}`));
    return out;
  }
  const h = head as SignedTreeHead;
  out.log_key_id = sr.key_id;
  const root = parseHash(p.root_hash);
  const sthRoot = parseHash(h.root_hash);
  if (!root) errors.push('proof.root_hash: not a 32-byte hex hash');
  if (!isSize(p.tree_size) || !isSize(p.leaf_index)) errors.push('proof.tree_size / leaf_index: not non-negative integers');
  if (root && sthRoot && !bytesEqual(root, sthRoot)) errors.push('proof.root_hash does not match the signed tree head');
  if (p.tree_size !== h.tree_size) errors.push(`proof.tree_size ${String(p.tree_size)} does not match the signed tree head ${String(h.tree_size)}`);
  if (!Array.isArray(p.audit_path)) errors.push('proof.audit_path: not an array');
  const path = Array.isArray(p.audit_path) ? p.audit_path.map(parseHash) : [];
  if (path.some((x) => x === null)) errors.push('proof.audit_path: every entry must be a 32-byte hex hash');
  if (errors.length) return out;

  let leaf: Uint8Array;
  try {
    leaf = await receiptLeafHash(receipt);
  } catch (e) {
    errors.push(`receipt canonicalization failed: ${(e as Error).message}`);
    return out;
  }
  const ok = await verifyInclusion({
    leafIndex: p.leaf_index, treeSize: p.tree_size, leaf,
    path: path as Uint8Array[], root: sthRoot as Uint8Array,
  });
  if (!ok) {
    errors.push('audit path does not lead from this receipt to the signed root');
    return out;
  }
  out.status = 'included';
  out.tree_size = p.tree_size;
  out.leaf_index = p.leaf_index;
  return out;
}

// ── Consistency between two signed tree heads ─────────────────────────────────

export interface ConsistencyResult {
  valid: boolean;
  errors: string[];
}

/** Prove `newer` extends `older` without rewriting history. Both STHs must
 *  verify under pinned log keys, belong to the same log, and the roots come
 *  from the STHs, never from the proof document. */
export async function verifySthConsistency(
  older: unknown,
  newer: unknown,
  proof: unknown,
  logKeys: LogKeyEntry[] | undefined,
  opts: SthOptions = {},
): Promise<ConsistencyResult> {
  const errors: string[] = [];
  const out: ConsistencyResult = { valid: false, errors };
  // Checked once here so a mixed set is one error, not one per STH.
  const km = logKeyMode(logKeys, opts.receiptKeys);
  if (km.error) {
    errors.push(km.error);
    return out;
  }
  const a = await verifySth(older, logKeys, opts);
  const b = await verifySth(newer, logKeys, opts);
  if (!a.valid) errors.push(...a.errors.map((e) => `older sth: ${e}`));
  if (!b.valid) errors.push(...b.errors.map((e) => `newer sth: ${e}`));
  if (errors.length) return out;
  if (a.log_id && b.log_id && a.log_id !== b.log_id) {
    errors.push(`sths are from different logs: ${a.log_id} vs ${b.log_id}`);
    return out;
  }
  const o = older as SignedTreeHead;
  const n = newer as SignedTreeHead;
  const oRoot = parseHash(o.root_hash) as Uint8Array;
  const nRoot = parseHash(n.root_hash) as Uint8Array;
  if (n.tree_size < o.tree_size) {
    errors.push(`newer sth tree_size ${n.tree_size} is smaller than older ${o.tree_size} (rollback)`);
    return out;
  }
  if (n.tree_size === o.tree_size) {
    if (!bytesEqual(oRoot, nRoot)) errors.push(`two different roots for tree_size ${n.tree_size} (fork)`);
    out.valid = errors.length === 0;
    return out;
  }
  if (!proof || typeof proof !== 'object') {
    errors.push('consistency proof must be an object');
    return out;
  }
  const p = proof as ConsistencyProof;
  if (p.first !== o.tree_size || p.second !== n.tree_size) {
    errors.push(`proof covers ${String(p.first)}→${String(p.second)}, sths are ${o.tree_size}→${n.tree_size}`);
  }
  if (p.first_root !== undefined) {
    const r = parseHash(p.first_root);
    if (!r || !bytesEqual(r, oRoot)) errors.push('proof.first_root does not match the older signed tree head');
  }
  if (p.second_root !== undefined) {
    const r = parseHash(p.second_root);
    if (!r || !bytesEqual(r, nRoot)) errors.push('proof.second_root does not match the newer signed tree head');
  }
  if (!Array.isArray(p.proof)) errors.push('proof.proof: not an array');
  const nodes = Array.isArray(p.proof) ? p.proof.map(parseHash) : [];
  if (nodes.some((x) => x === null)) errors.push('proof.proof: every entry must be a 32-byte hex hash');
  if (errors.length) return out;
  const ok = await verifyConsistency({
    first: o.tree_size, second: n.tree_size, firstRoot: oRoot, secondRoot: nRoot,
    proof: nodes as Uint8Array[],
  });
  if (!ok) errors.push('consistency proof does not verify: the newer tree does not extend the older');
  out.valid = errors.length === 0;
  return out;
}

// ── LogMonitor ────────────────────────────────────────────────────────────────

/** Persists the last STH a verifier accepted, per log. Implement over memory,
 *  a file, Workers KV, localStorage, a database: anything durable enough that
 *  a restart does not forget what the log already showed you. One LogMonitor
 *  serializes its own observe() calls; two monitors (or processes) sharing
 *  one store are not coordinated, so give each its own store or make put()
 *  a compare-and-swap on the previous tree_size. */
export interface SthStore {
  get(logId: string): Promise<SignedTreeHead | null>;
  put(logId: string, sth: SignedTreeHead): Promise<void>;
}

export class MemorySthStore implements SthStore {
  private m = new Map<string, SignedTreeHead>();
  async get(logId: string): Promise<SignedTreeHead | null> { return this.m.get(logId) ?? null; }
  async put(logId: string, sth: SignedTreeHead): Promise<void> { this.m.set(logId, sth); }
}

export type MonitorStatus = 'first' | 'unchanged' | 'advanced' | 'invalid' | 'fork' | 'rollback' | 'unproven';

export interface MonitorResult {
  ok: boolean;
  status: MonitorStatus;
  errors: string[];
  previous_tree_size?: number;
  tree_size?: number;
}

export interface LogMonitorOptions extends SthOptions {
  /** The log this monitor watches; also the store key. Required: if the
   *  bucket came from the STH's own log_id, a log whose key is not bound to
   *  a log_id could sign a head under a fresh log_id and start a new,
   *  unchecked history ('first') instead of being caught as a fork. */
  logId: string;
  logKeys: LogKeyEntry[];
  store?: SthStore;
  /** Fetch a consistency proof from the log when observe() is not given one,
   *  e.g. GET /v1/receipts/log/consistency?first=&second= . */
  fetchConsistency?: (first: number, second: number) => Promise<ConsistencyProof>;
}

/** Watches one log. Every STH it is shown must verify, and every advance must
 *  come with a consistency proof from the last accepted STH. A smaller tree,
 *  a second root for the same size, or an unprovable advance is reported and
 *  NOT stored, so the monitor keeps its last good view. A fork or rollback is
 *  evidence of log misbehaviour: keep both STHs. */
export class LogMonitor {
  private readonly o: LogMonitorOptions;
  private readonly store: SthStore;
  /** Tail of the observe() queue: each call runs after the previous one, so
   *  two concurrent advances cannot both read the same `prev` and the
   *  smaller one overwrite the larger. */
  private tail: Promise<unknown> = Promise.resolve();

  constructor(opts: LogMonitorOptions) {
    // A constructor misuse, not untrusted input, so this one throws.
    if (!opts || typeof opts.logId !== 'string' || opts.logId === '') {
      throw new TypeError('LogMonitor: logId is required (the log this monitor watches)');
    }
    const km = logKeyMode(opts.logKeys, opts.receiptKeys);
    if (km.error) throw new TypeError(`LogMonitor: ${km.error}`);
    this.o = opts;
    this.store = opts.store ?? new MemorySthStore();
  }

  /** The last STH this monitor accepted. */
  last(): Promise<SignedTreeHead | null> {
    return this.store.get(this.o.logId);
  }

  observe(sth: unknown, proof?: ConsistencyProof): Promise<MonitorResult> {
    const run = this.tail.then(() => this.observeNow(sth, proof));
    this.tail = run.catch(() => undefined);
    return run;
  }

  private async observeNow(sth: unknown, proof?: ConsistencyProof): Promise<MonitorResult> {
    // verifySth with opts.logId refuses an STH naming another log.
    const sr = await verifySth(sth, this.o.logKeys, this.o);
    if (!sr.valid) return { ok: false, status: 'invalid', errors: sr.errors };
    const next = sth as SignedTreeHead;
    const id = this.o.logId;
    const prev = await this.store.get(id);
    if (!prev) {
      await this.store.put(id, next);
      return { ok: true, status: 'first', errors: [], tree_size: next.tree_size };
    }
    const base = { previous_tree_size: prev.tree_size, tree_size: next.tree_size };
    if (next.tree_size < prev.tree_size) {
      return { ok: false, status: 'rollback', errors: [`log shrank from ${prev.tree_size} to ${next.tree_size}`], ...base };
    }
    if (next.tree_size === prev.tree_size) {
      const same = bytesEqual(parseHash(prev.root_hash) as Uint8Array, parseHash(next.root_hash) as Uint8Array);
      return same
        ? { ok: true, status: 'unchanged', errors: [], ...base }
        : { ok: false, status: 'fork', errors: [`two signed roots for tree_size ${next.tree_size}`], ...base };
    }
    let p = proof;
    if (!p && this.o.fetchConsistency) {
      try {
        p = await this.o.fetchConsistency(prev.tree_size, next.tree_size);
      } catch (e) {
        return { ok: false, status: 'unproven', errors: [`consistency fetch failed: ${(e as Error).message}`], ...base };
      }
    }
    if (!p) {
      return { ok: false, status: 'unproven', errors: ['advance without a consistency proof'], ...base };
    }
    const cr = await verifySthConsistency(prev, next, p, this.o.logKeys, this.o);
    // A proof that fails is not by itself proof of a fork (the log may have
    // served a bad proof); it is an advance the monitor cannot accept.
    if (!cr.valid) return { ok: false, status: 'unproven', errors: cr.errors, ...base };
    await this.store.put(id, next);
    return { ok: true, status: 'advanced', errors: [], ...base };
  }
}
