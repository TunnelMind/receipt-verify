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
// The verifier is deliberately STRICT-by-default. Pass `allowKeyMismatch`
// to convert a key-bundle mismatch into a warning instead of an error
// (useful when verifying receipts during a key-rotation overlap window).
import { canonicalize, canonicalizeBytes } from './jcs.js';
import { fetchKeyBundle, resolveKey, } from './keys.js';
import { fetchRevocations, isKeyRevoked, isReceiptRevoked, } from './revocation.js';
const subtle = globalThis.crypto.subtle;
export const RECEIPT_VERSION = '1.0';
const STRENGTH_RANK = {
    'self-asserted': 0,
    software: 1,
    'tee-tpm': 2,
    'silicon-root': 3,
};
// ── Helpers ───────────────────────────────────────────────────────────────────
function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(new ArrayBuffer(bin.length));
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
function bytesToHex(buf) {
    const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    return Array.from(arr).map((x) => x.toString(16).padStart(2, '0')).join('');
}
async function sha256HexPrefixed(bytes) {
    return '0x' + bytesToHex(await subtle.digest('SHA-256', bytes));
}
/** Coerce TextEncoder output (ArrayBufferLike-backed) to ArrayBuffer-backed
 *  Uint8Array so SubtleCrypto's strict BufferSource typing is satisfied. */
function toAB(u) {
    const buf = new ArrayBuffer(u.byteLength);
    new Uint8Array(buf).set(u);
    return new Uint8Array(buf);
}
function buildSigningObject(receipt) {
    // Per spec §3 step 2: signing object = receipt with `payload` and
    // `signature.value` omitted, then JCS-canonicalized.
    const { payload: _payload, signature, ...rest } = receipt;
    const { value: _value, ...sigNoValue } = signature;
    void _payload;
    void _value;
    return { ...rest, signature: sigNoValue };
}
// ── Main entry point ──────────────────────────────────────────────────────────
/**
 * Verify a TunnelMind Receipt v1.0 against the published spec.
 *
 * Performs:
 *   1. version check
 *   2. payload_hash recompute
 *   3. signature reconstruction + Ed25519 verify against embedded public_key
 *   4. optional key-bundle resolution + match
 *   5. attestation-strength ceiling rule
 *   6. optional revocation check (key + receipt)
 *   7. chain sequence sanity (warn-only)
 */
export async function verifyReceipt(receipt, opts = {}) {
    const errors = [];
    const warnings = [];
    const out = { valid: false, errors, warnings };
    if (!receipt || typeof receipt !== 'object') {
        errors.push('receipt must be a non-null object');
        return out;
    }
    out.receipt_id = receipt.receipt_id;
    out.key_id = receipt.signature?.key_id;
    out.attestation_strength = receipt.attestation_strength;
    // 1. Version
    if (receipt.receipt_version !== RECEIPT_VERSION) {
        errors.push(`receipt_version: expected ${RECEIPT_VERSION}, got ${String(receipt.receipt_version)}`);
        return out;
    }
    // 2. payload_hash
    try {
        const computed = await sha256HexPrefixed(toAB(canonicalizeBytes(receipt.payload)));
        if (computed !== receipt.payload_hash) {
            errors.push(`payload_hash mismatch: computed ${computed}, claimed ${receipt.payload_hash}`);
        }
    }
    catch (e) {
        errors.push(`payload canonicalization failed: ${e.message}`);
    }
    // 3. Signature
    if (!receipt.signature?.algorithm || receipt.signature.algorithm !== 'Ed25519') {
        errors.push(`unsupported signature algorithm: ${String(receipt.signature?.algorithm)}`);
    }
    else {
        try {
            const pubBytes = b64ToBytes(receipt.signature.public_key);
            if (pubBytes.length !== 32) {
                errors.push(`signature.public_key: expected 32 raw bytes, got ${pubBytes.length}`);
            }
            else {
                const pubKey = await subtle.importKey('raw', pubBytes, { name: 'Ed25519' }, false, ['verify']);
                const sig = b64ToBytes(receipt.signature.value);
                const ok = await subtle.verify('Ed25519', pubKey, sig, toAB(canonicalizeBytes(buildSigningObject(receipt))));
                if (!ok)
                    errors.push('Ed25519 signature did not verify');
            }
        }
        catch (e) {
            errors.push(`signature verification failed: ${e.message}`);
        }
    }
    // 4. Key bundle resolution
    let resolvedKey = null;
    if (!opts.noFetchKeys && receipt.signature?.key_id) {
        try {
            const bundle = await fetchKeyBundle({
                bundle: opts.keys,
                url: opts.keysUrl,
                fetcher: opts.fetcher,
            });
            resolvedKey = resolveKey(bundle, receipt.signature.key_id);
            if (!resolvedKey) {
                const msg = `signature.key_id ${receipt.signature.key_id} not present in key bundle`;
                if (opts.allowKeyMismatch)
                    warnings.push(msg);
                else
                    errors.push(msg);
            }
            else if (resolvedKey.public_key !== receipt.signature.public_key) {
                const msg = `key bundle public_key for ${receipt.signature.key_id} does not match the receipt's embedded public_key`;
                if (opts.allowKeyMismatch)
                    warnings.push(msg);
                else
                    errors.push(msg);
            }
        }
        catch (e) {
            warnings.push(`key bundle fetch failed (verification continues against embedded key): ${e.message}`);
        }
    }
    // 5. Attestation-strength ceiling
    if (resolvedKey?.attestation_strength) {
        const tokenRank = STRENGTH_RANK[receipt.attestation_strength] ?? -1;
        const keyRank = STRENGTH_RANK[resolvedKey.attestation_strength] ?? -1;
        if (tokenRank > keyRank) {
            errors.push(`attestation_strength ceiling violated: receipt=${receipt.attestation_strength} > key=${resolvedKey.attestation_strength}`);
        }
    }
    // 6. Revocation
    if (!opts.noFetchRevocations) {
        try {
            const feed = await fetchRevocations({
                feed: opts.revocations,
                url: opts.revocationsUrl,
                fetcher: opts.fetcher,
            });
            if (receipt.signature?.key_id) {
                const k = isKeyRevoked(feed, receipt.signature.key_id);
                if (k.revoked) {
                    // Per spec §8.3 step 3: receipts signed AFTER revoked_at must be rejected;
                    // receipts signed before that can survive with a warning.
                    const issued = Date.parse(receipt.timestamp);
                    const revoked = Date.parse(k.revoked_at ?? '');
                    if (Number.isFinite(issued) && Number.isFinite(revoked) && issued < revoked) {
                        warnings.push(`signing key was rotated out of service at ${k.revoked_at} (receipt predates rotation); reason: ${k.reason}`);
                    }
                    else {
                        errors.push(`signing key ${receipt.signature.key_id} revoked at ${k.revoked_at}: ${k.reason}`);
                    }
                }
            }
            if (receipt.receipt_id) {
                const r = isReceiptRevoked(feed, receipt.receipt_id);
                if (r.revoked) {
                    errors.push(`receipt ${receipt.receipt_id} revoked at ${r.revoked_at}: ${r.reason}`);
                }
            }
        }
        catch (e) {
            warnings.push(`revocation feed fetch failed (verification continues): ${e.message}`);
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
export { DEFAULT_KEYS_URL, fetchKeyBundle, resolveKey, clearKeyCache, } from './keys.js';
export { DEFAULT_REVOCATIONS_URL, fetchRevocations, isKeyRevoked, isReceiptRevoked, clearRevocationCache, } from './revocation.js';
//# sourceMappingURL=index.js.map