import { canonicalize, canonicalizeBytes, type JsonValue } from './jcs.js';
import { type KeyBundle, type AttestationStrength } from './keys.js';
import { type RevocationFeed } from './revocation.js';
export declare const RECEIPT_VERSION = "1.0";
export interface ReceiptSignature {
    algorithm: 'Ed25519';
    key_id: string;
    public_key: string;
    value: string;
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
    timestamp_proof?: {
        method: string;
        [k: string]: unknown;
    };
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
    /** Provide a pre-fetched key bundle. If omitted and `noFetchKeys` is false,
     *  the verifier fetches https://tunnelmind.ai/.well-known/receipt-signing-key.json. */
    keys?: KeyBundle;
    /** Skip key-bundle resolution entirely (verify only against the embedded public_key). */
    noFetchKeys?: boolean;
    /** Override the well-known keys URL (e.g., self-hosted issuer). */
    keysUrl?: string;
    /** Provide a pre-fetched revocations feed. If omitted and `noFetchRevocations` is
     *  false, the verifier fetches https://tunnelmind.ai/.well-known/receipt-revocations.json. */
    revocations?: RevocationFeed;
    /** Skip revocation check entirely (offline mode). */
    noFetchRevocations?: boolean;
    /** Override the well-known revocations URL. */
    revocationsUrl?: string;
    /** When true, key-bundle public_key mismatch is a warning, not an error.
     *  Use during rotation-overlap windows when both old + new key are valid. */
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
export declare function verifyReceipt(receipt: Receipt, opts?: VerifyOptions): Promise<VerifyResult>;
export { canonicalize, canonicalizeBytes };
export { DEFAULT_KEYS_URL, fetchKeyBundle, resolveKey, clearKeyCache, } from './keys.js';
export { DEFAULT_REVOCATIONS_URL, fetchRevocations, isKeyRevoked, isReceiptRevoked, clearRevocationCache, } from './revocation.js';
export type { KeyBundle, SigningKeyEntry, AttestationStrength, } from './keys.js';
export type { RevocationFeed, RevokedKey, RevokedReceipt, KeyRevocationCheck, ReceiptRevocationCheck, } from './revocation.js';
export type { JsonValue } from './jcs.js';
//# sourceMappingURL=index.d.ts.map