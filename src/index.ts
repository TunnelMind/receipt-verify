// @tunnelmindai/receipt-verify — reference verifier for the
// TunnelMind Receipt Format v1.0.
//
// Spec: https://tunnelmind.ai/standards/receipt-format/v1
// Repo: https://github.com/TunnelMind/receipt-verify
//
// This package implements §4 (Verification procedure) end-to-end plus
// §8 (Revocation) lookups. Zero runtime dependencies. Targets WebCrypto
// SubtleCrypto + fetch — runs on Node ≥18, Cloudflare Workers, Deno, Bun.
//
// The verifier is deliberately STRICT-by-default. Every key that signs must
// come from the key bundle and be usable at the receipt's timestamp (status
// active/rotated, inside [created_at, rotation_after]). `allowKeyMismatch`
// only lets a receipt whose embedded public_key belongs to a DIFFERENT
// usable key in the same bundle verify against that key, with a warning
// (key-rotation overlap). The embedded public_key is never verified against.

import { canonicalize, canonicalizeBytes, type JsonValue } from './jcs.js';
import {
  fetchKeyBundle,
  resolveKey,
  type KeyBundle,
  type SigningKeyEntry,
  keyUsableAt,
  type AttestationStrength,
} from './keys.js';
import { PINNED_KEY_BUNDLE } from './pinned-keys.js';
import {
  fetchRevocations,
  isKeyRevoked,
  isReceiptRevoked,
  type RevocationFeed,
} from './revocation.js';

const subtle = globalThis.crypto.subtle;

export const RECEIPT_VERSION = '1.0';

const STRENGTH_RANK: Record<AttestationStrength, number> = {
  'self-asserted': 0,
  software:        1,
  'tee-tpm':       2,
  'silicon-root':  3,
};

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ReceiptSignature {
  algorithm: 'Ed25519';
  key_id: string;
  public_key: string; // base64 raw 32-byte Ed25519
  value: string;      // base64 Ed25519 signature
}

export interface ReceiptChain {
  previous_receipt_hash: string | null;
  sequence: number;
}

export interface ReceiptSource {
  lens: string;
  endpoint: string;
  node_id: string;
}

export interface Receipt {
  receipt_version: string;
  receipt_id: string;
  timestamp: string;
  timestamp_proof?: { method: string; [k: string]: unknown };
  source: ReceiptSource;
  subject?: string;
  attestation_strength: AttestationStrength;
  payload_hash: string;
  payload: JsonValue;
  chain: ReceiptChain;
  signature: ReceiptSignature;
  extensions?: Record<string, unknown>;
}

export interface VerifyOptions {
  /** Provide a pre-fetched key bundle. If omitted, the verifier fetches
   *  `keysUrl` when given, else uses the pinned PINNED_KEY_BUNDLE. */
  keys?: KeyBundle;
  /** Never fetch `keysUrl`; fall back to the pinned bundle. The embedded
   *  public_key is never trusted on its own. */
  noFetchKeys?: boolean;
  /** Fetch the key bundle from this URL (e.g., self-hosted issuer). */
  keysUrl?: string;
  /** Provide a pre-fetched revocations feed. If omitted, the verifier fetches
   *  `revocationsUrl` (default https://tunnelmind.ai/.well-known/receipt-revocations.json);
   *  a failed fetch makes the receipt invalid. Offline callers pass this. */
  revocations?: RevocationFeed;
  /** UNSAFE: disables revocation checking, so a receipt signed by a revoked
   *  or compromised key verifies. Offline callers should pass `revocations`
   *  instead. */
  unsafeSkipRevocations?: boolean;
  /** Override the well-known revocations URL. */
  revocationsUrl?: string;
  /** When the receipt's embedded public_key differs from the bundle key for
   *  its key_id, accept it (with a warning) only if that public_key is
   *  another key in the same bundle that is active or rotated and whose
   *  [created_at, rotation_after] window covers the receipt timestamp; the
   *  signature is then verified against that bundle key. A key absent from
   *  the bundle is never accepted. Use during rotation-overlap windows. */
  allowKeyMismatch?: boolean;
  /** Custom fetch (e.g., for offline tests). */
  fetcher?: typeof fetch;
}

export interface VerifyResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  /** Receipt metadata extracted on best-effort basis (may be undefined if parse fails). */
  receipt_id?: string;
  key_id?: string;
  attestation_strength?: AttestationStrength;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(arr).map((x) => x.toString(16).padStart(2, '0')).join('');
}

async function sha256HexPrefixed(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  return '0x' + bytesToHex(await subtle.digest('SHA-256', bytes));
}

/** Coerce TextEncoder output (ArrayBufferLike-backed) to ArrayBuffer-backed
 *  Uint8Array so SubtleCrypto's strict BufferSource typing is satisfied. */
function toAB(u: Uint8Array): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(u.byteLength);
  new Uint8Array(buf).set(u);
  return new Uint8Array(buf);
}

function buildSigningObject(receipt: Receipt): JsonValue {
  // Per spec §3 step 2: signing object = receipt with `payload` and
  // `signature.value` omitted, then JCS-canonicalized.
  const { payload: _payload, signature, ...rest } = receipt;
  const { value: _value, ...sigNoValue } = signature;
  void _payload; void _value;
  return { ...rest, signature: sigNoValue } as unknown as JsonValue;
}

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Verify a TunnelMind Receipt v1.0 against the published spec.
 *
 * Performs:
 *   1. version check
 *   2. payload_hash recompute
 *   3. key_id resolution against the key bundle (keys > keysUrl > pinned),
 *      plus the key's status + [created_at, rotation_after] window check
 *   4. signature reconstruction + Ed25519 verify against the bundle's public_key
 *   5. attestation-strength ceiling rule
 *   6. optional revocation check (key + receipt)
 *   7. chain sequence sanity (warn-only)
 */
export async function verifyReceipt(
  receipt: Receipt,
  opts: VerifyOptions = {},
): Promise<VerifyResult> {
  const errors: string[]   = [];
  const warnings: string[] = [];
  const out: VerifyResult = { valid: false, errors, warnings };

  if (!receipt || typeof receipt !== 'object') {
    errors.push('receipt must be a non-null object');
    return out;
  }

  out.receipt_id           = receipt.receipt_id;
  out.key_id               = receipt.signature?.key_id;
  out.attestation_strength = receipt.attestation_strength;

  // 1. Version
  if (receipt.receipt_version !== RECEIPT_VERSION) {
    errors.push(
      `receipt_version: expected ${RECEIPT_VERSION}, got ${String(receipt.receipt_version)}`,
    );
    return out;
  }

  // 2. payload_hash
  try {
    const computed = await sha256HexPrefixed(toAB(canonicalizeBytes(receipt.payload)));
    if (computed !== receipt.payload_hash) {
      errors.push(`payload_hash mismatch: computed ${computed}, claimed ${receipt.payload_hash}`);
    }
  } catch (e) {
    errors.push(`payload canonicalization failed: ${(e as Error).message}`);
  }

  // 3. Key resolution. The signature is bound to the KEY BUNDLE, never to the
  // receipt's embedded public_key: anyone can embed their own key and sign,
  // so trusting it would accept any self-signed forgery. Bundle precedence:
  // opts.keys > fetched opts.keysUrl > the pinned bundle shipped with the
  // package (so the default path needs no network).
  const keyId = receipt.signature?.key_id;
  let bundle: KeyBundle | null = null;
  let resolvedKey: SigningKeyEntry | null = null;
  if (typeof keyId !== 'string' || keyId === '') {
    errors.push('signature.key_id: required non-empty string');
  } else {
    try {
      bundle = opts.keys
        ?? (opts.keysUrl && !opts.noFetchKeys
          ? await fetchKeyBundle({ url: opts.keysUrl, fetcher: opts.fetcher })
          : PINNED_KEY_BUNDLE);
      resolvedKey = resolveKey(bundle, keyId);
      // allowKeyMismatch never rescues an unresolved key_id.
      if (!resolvedKey) errors.push(`signature.key_id ${keyId} not present in key bundle`);
    } catch (e) {
      errors.push(`key bundle fetch failed: ${(e as Error).message}`);
    }
  }
  // The key used for steps 4–5: the resolved bundle key, or under
  // allowKeyMismatch another bundle entry matched by public_key; never the
  // embedded key. Errors above don't clear it, so the signature is still
  // checked and reported against the bundle key.
  let signingKey: SigningKeyEntry | null = resolvedKey;
  const tsMs = Date.parse(receipt.timestamp);
  if (resolvedKey && bundle) {
    if (!Number.isFinite(tsMs)) {
      errors.push(`timestamp: not a valid date: ${String(receipt.timestamp)}`);
    } else if (receipt.signature.public_key !== undefined
        && receipt.signature.public_key !== resolvedKey.public_key) {
      // The named key A's status/window is deliberately not checked here: B is the signer.
      const embedded = receipt.signature.public_key;
      const alt = opts.allowKeyMismatch
        ? bundle.keys.find((k) => k.key_id !== keyId && k.public_key === embedded
            && keyUsableAt(k, tsMs) === null)
        : undefined;
      if (alt) {
        signingKey = alt;
        warnings.push(
          `receipt names key_id ${keyId} but its public_key is bundle key ${alt.key_id}; verified against ${alt.key_id}`,
        );
      } else {
        errors.push(
          `key bundle public_key for ${keyId} does not match the receipt's embedded public_key`,
        );
      }
    } else {
      // Window check applies to the key the receipt resolves to, flag or not.
      const why = keyUsableAt(resolvedKey, tsMs);
      if (why) errors.push(why);
    }
  }

  // 4. Signature, verified against the selected bundle key only.
  if (!receipt.signature?.algorithm || receipt.signature.algorithm !== 'Ed25519') {
    errors.push(`unsupported signature algorithm: ${String(receipt.signature?.algorithm)}`);
  } else if (signingKey) {
    try {
      const pubBytes = b64ToBytes(signingKey.public_key);
      if (pubBytes.length !== 32) {
        errors.push(`key bundle public_key: expected 32 raw bytes, got ${pubBytes.length}`);
      } else {
        const pubKey = await subtle.importKey(
          'raw', pubBytes,
          { name: 'Ed25519' },
          false, ['verify'],
        );
        const sig = b64ToBytes(receipt.signature.value);
        const ok  = await subtle.verify(
          'Ed25519', pubKey, sig,
          toAB(canonicalizeBytes(buildSigningObject(receipt))),
        );
        if (!ok) errors.push('Ed25519 signature did not verify');
      }
    } catch (e) {
      errors.push(`signature verification failed: ${(e as Error).message}`);
    }
  }

  // 5. Attestation-strength ceiling
  if (signingKey?.attestation_strength) {
    const tokenRank = STRENGTH_RANK[receipt.attestation_strength] ?? -1;
    const keyRank   = STRENGTH_RANK[signingKey.attestation_strength] ?? -1;
    if (tokenRank > keyRank) {
      errors.push(
        `attestation_strength ceiling violated: receipt=${receipt.attestation_strength} > key=${signingKey.attestation_strength}`,
      );
    }
  }

  // 6. Revocation
  if (!opts.unsafeSkipRevocations) {
    try {
      const feed = await fetchRevocations({
        feed:    opts.revocations,
        url:     opts.revocationsUrl,
        fetcher: opts.fetcher,
      });
      // Check the named key_id AND the key that actually verified: under
      // allowKeyMismatch they differ, and a feed-revoked signer must not
      // slip through by naming another bundle key.
      const ids = new Set([receipt.signature?.key_id, signingKey?.key_id]);
      for (const id of ids) {
        if (!id) continue;
        const k = isKeyRevoked(feed, id);
        if (k.revoked) {
          // Per spec §8.3 step 3: receipts signed AFTER revoked_at must be rejected;
          // receipts signed before that can survive with a warning. Not for a
          // compromised key: receipt.timestamp is signed by whoever holds the
          // key, so an attacker can backdate it past revoked_at.
          const issued = Date.parse(receipt.timestamp);
          const revoked = Date.parse(k.revoked_at ?? '');
          if (k.reason !== 'compromise' && Number.isFinite(issued) && Number.isFinite(revoked) && issued < revoked) {
            warnings.push(`signing key was rotated out of service at ${k.revoked_at} (receipt predates rotation); reason: ${k.reason}`);
          } else {
            errors.push(`signing key ${id} revoked at ${k.revoked_at}: ${k.reason}`);
          }
        }
      }
      if (receipt.receipt_id) {
        const r = isReceiptRevoked(feed, receipt.receipt_id);
        if (r.revoked) {
          errors.push(`receipt ${receipt.receipt_id} revoked at ${r.revoked_at}: ${r.reason}`);
        }
      }
    } catch (e) {
      // Fail closed: an attacker who can block the feed must not thereby
      // un-revoke a key. The remaining checks still run for diagnostics.
      errors.push(`revocation feed fetch failed: ${(e as Error).message}`);
    }
  }

  // 7. Chain sequence sanity (warn-only)
  if (receipt.chain) {
    if (receipt.chain.previous_receipt_hash && receipt.chain.sequence === 0) {
      warnings.push('chain.sequence is 0 but previous_receipt_hash is non-null');
    }
    if (!receipt.chain.previous_receipt_hash && receipt.chain.sequence > 0) {
      warnings.push('chain.sequence > 0 but previous_receipt_hash is null');
    }
  }

  out.valid = errors.length === 0;
  return out;
}

// Re-exports for advanced consumers
export { canonicalize, canonicalizeBytes };
export {
  DEFAULT_KEYS_URL,
  fetchKeyBundle,
  resolveKey,
  keyUsableAt,
  clearKeyCache,
} from './keys.js';
export { PINNED_KEY_BUNDLE, PINNED_KEYS_FETCHED_AT } from './pinned-keys.js';
export {
  DEFAULT_REVOCATIONS_URL,
  REVOCATION_CACHE_TTL_MS,
  fetchRevocations,
  isKeyRevoked,
  isReceiptRevoked,
  clearRevocationCache,
} from './revocation.js';
export type {
  KeyBundle,
  SigningKeyEntry,
  AttestationStrength,
} from './keys.js';
export type {
  RevocationFeed,
  RevokedKey,
  RevokedReceipt,
  KeyRevocationCheck,
  ReceiptRevocationCheck,
} from './revocation.js';
export type { JsonValue } from './jcs.js';
