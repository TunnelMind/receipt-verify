export declare const DEFAULT_REVOCATIONS_URL = "https://tunnelmind.ai/.well-known/receipt-revocations.json";
export interface RevokedKey {
    key_id: string;
    revoked_at: string;
    reason: string;
    replacement_key_id?: string | null;
}
export interface RevokedReceipt {
    receipt_id: string;
    revoked_at: string;
    reason: string;
}
export interface RevocationFeed {
    feed_version: number;
    updated_at: string;
    revoked_keys: RevokedKey[];
    revoked_receipts: RevokedReceipt[];
}
export interface FetchRevocationsOptions {
    url?: string;
    noCache?: boolean;
    feed?: RevocationFeed;
    fetcher?: typeof fetch;
}
export declare function fetchRevocations(opts?: FetchRevocationsOptions): Promise<RevocationFeed>;
export interface KeyRevocationCheck {
    revoked: boolean;
    revoked_at?: string;
    reason?: string;
    replacement_key_id?: string | null;
}
export interface ReceiptRevocationCheck {
    revoked: boolean;
    revoked_at?: string;
    reason?: string;
}
export declare function isKeyRevoked(feed: RevocationFeed, keyId: string): KeyRevocationCheck;
export declare function isReceiptRevoked(feed: RevocationFeed, receiptId: string): ReceiptRevocationCheck;
export declare function clearRevocationCache(): void;
//# sourceMappingURL=revocation.d.ts.map