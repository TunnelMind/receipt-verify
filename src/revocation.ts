// Revocation feed per Receipt Format v1.0 §8.
//
// Two flavors:
//   - revoked_keys[]     — invalidate signatures by key_id after revoked_at
//   - revoked_receipts[] — issuer-retracted individual receipts (by uuidv7)
//
// Production verifiers MAY also use the single-item lookup at
// `https://data.tunnelmind.ai/v1/receipt/revoked?key_id=...|?id=...` —
// this module concerns itself only with the static feed.

export const DEFAULT_REVOCATIONS_URL =
  'https://tunnelmind.ai/.well-known/receipt-revocations.json';

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

let _cache: { feed: RevocationFeed; fetchedAt: number } | null = null;

export interface FetchRevocationsOptions {
  url?: string;
  noCache?: boolean;
  feed?: RevocationFeed;
  fetcher?: typeof fetch;
}

export async function fetchRevocations(opts: FetchRevocationsOptions = {}): Promise<RevocationFeed> {
  if (opts.feed) return opts.feed;
  if (!opts.noCache && _cache) return _cache.feed;
  const url = opts.url ?? DEFAULT_REVOCATIONS_URL;
  const f = opts.fetcher ?? fetch;
  const r = await f(url);
  if (!r.ok) throw new Error(`fetchRevocations: ${url} returned ${r.status}`);
  const j = (await r.json()) as Partial<RevocationFeed>;
  const normalized: RevocationFeed = {
    feed_version:     typeof j.feed_version === 'number' ? j.feed_version : 0,
    updated_at:       j.updated_at ?? new Date().toISOString(),
    revoked_keys:     Array.isArray(j.revoked_keys)     ? j.revoked_keys     : [],
    revoked_receipts: Array.isArray(j.revoked_receipts) ? j.revoked_receipts : [],
  };
  _cache = { feed: normalized, fetchedAt: Date.now() };
  return normalized;
}

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

export function isKeyRevoked(feed: RevocationFeed, keyId: string): KeyRevocationCheck {
  const m = feed.revoked_keys.find((k) => k.key_id === keyId);
  if (!m) return { revoked: false };
  return {
    revoked: true,
    revoked_at: m.revoked_at,
    reason: m.reason,
    replacement_key_id: m.replacement_key_id ?? null,
  };
}

export function isReceiptRevoked(feed: RevocationFeed, receiptId: string): ReceiptRevocationCheck {
  const m = feed.revoked_receipts.find((r) => r.receipt_id.toLowerCase() === receiptId.toLowerCase());
  if (!m) return { revoked: false };
  return { revoked: true, revoked_at: m.revoked_at, reason: m.reason };
}

export function clearRevocationCache(): void {
  _cache = null;
}
