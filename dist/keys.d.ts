export declare const DEFAULT_KEYS_URL = "https://tunnelmind.ai/.well-known/receipt-signing-key.json";
export type AttestationStrength = 'self-asserted' | 'software' | 'tee-tpm' | 'silicon-root';
export interface SigningKeyEntry {
    key_id: string;
    algorithm: 'Ed25519';
    public_key: string;
    public_key_encoding?: 'raw-32-byte-base64' | string;
    status?: 'active' | 'rotated' | 'revoked';
    created_at?: string;
    rotation_after?: string;
    attestation_strength?: AttestationStrength;
    operator?: string;
    purpose?: string;
}
export interface KeyBundle {
    service?: string;
    spec?: string;
    format_version?: string;
    updated_at?: string;
    keys: SigningKeyEntry[];
    rotation_policy?: unknown;
}
export interface ResolveKeyOptions {
    /** Override the well-known URL (e.g., for self-hosted issuers). */
    url?: string;
    /** If true, bypass the in-memory cache and re-fetch. */
    noCache?: boolean;
    /** Provide a pre-fetched bundle (skip network entirely). */
    bundle?: KeyBundle;
    /** Custom fetch (e.g., for offline tests). */
    fetcher?: typeof fetch;
}
export declare function fetchKeyBundle(opts?: ResolveKeyOptions): Promise<KeyBundle>;
export declare function resolveKey(bundle: KeyBundle, keyId: string): SigningKeyEntry | null;
/** Reset the module-level key cache. Useful for tests + long-lived workers
 *  doing scheduled key refresh. */
export declare function clearKeyCache(): void;
//# sourceMappingURL=keys.d.ts.map