// Revocation feed per Receipt Format v1.0 §8: the issuer's list of keys that
// must no longer verify (revoked_keys, by key_id, from revoked_at) and of
// individual receipts it retracted (revoked_receipts, by uuidv7).
// Called by index.ts step 6, which applies the feed; a fetch that fails there
// is an error, so blocking the feed cannot un-revoke a key.
// Trust: the feed is trusted as a whole (the caller's object or the URL the
// caller chose). A fetched body is normalised, not validated: a missing or
// non-array revoked_keys / revoked_receipts counts as "nothing revoked" (the
// published feed starts empty), while a malformed entry inside an array
// throws in isKeyRevoked/isReceiptRevoked and index.ts reports that as an
// error. Cached per URL for REVOCATION_CACHE_TTL_MS.
// Production verifiers MAY instead use the single-item lookup at
// `https://data.tunnelmind.ai/v1/receipt/revoked?key_id=...|?id=...`.

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

// Keyed by URL so a feed from one issuer is never served for another; entries
// expire so a newly published revocation is seen within the TTL.
export const REVOCATION_CACHE_TTL_MS = 5 * 60 * 1000;
const _cache = new Map<string, { feed: RevocationFeed; fetchedAt: number }>();

export interface FetchRevocationsOptions {
  url?: string;
  noCache?: boolean;
  /** Max age of a cached feed; default REVOCATION_CACHE_TTL_MS. */
  ttlMs?: number;
  feed?: RevocationFeed;
  fetcher?: typeof fetch;
}

export async function fetchRevocations(opts: FetchRevocationsOptions = {}): Promise<RevocationFeed> {
  if (opts.feed) return opts.feed;
  const url = opts.url ?? DEFAULT_REVOCATIONS_URL;
  const hit = _cache.get(url);
  if (!opts.noCache && hit && Date.now() - hit.fetchedAt < (opts.ttlMs ?? REVOCATION_CACHE_TTL_MS)) return hit.feed;
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
  _cache.set(url, { feed: normalized, fetchedAt: Date.now() });
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

/** Whether the feed lists `keyId` (exact match: key ids are opaque) and, if
 *  so, when and why — the caller decides how revoked_at and reason apply. */
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

/** Whether the feed retracts `receiptId`. Case-insensitive because receipt
 *  ids are UUIDs (RFC 9562: hex digits compare case-insensitively) and only
 *  the feed side can differ — the receipt's own id is signed. */
export function isReceiptRevoked(feed: RevocationFeed, receiptId: string): ReceiptRevocationCheck {
  const m = feed.revoked_receipts.find((r) => r.receipt_id.toLowerCase() === receiptId.toLowerCase());
  if (!m) return { revoked: false };
  return { revoked: true, revoked_at: m.revoked_at, reason: m.reason };
}

export function clearRevocationCache(): void {
  _cache.clear();
}
