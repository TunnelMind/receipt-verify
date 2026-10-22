// Receipt signing-key bundle: the trust anchor of every verification. Spec
// §4 step 2: find the bundle key whose key_id matches the receipt's, confirm
// the receipt's embedded public_key equals it, verify against the bundle's.
// Called by index.ts step 3; fetches only when the caller names a keysUrl.
// Trust boundary: the bundle is trusted as a whole (it comes from the caller,
// the URL the caller chose, or pinned-keys.ts); a fetched body is validated
// only as "object with a `keys` array" — a malformed entry inside makes the
// receipt fail (resolveKey/keyUsableAt throw into index.ts's catch), never pass.
// Invariant: a fetched bundle is cached per URL, after validation, for
// KEY_BUNDLE_CACHE_TTL_MS, so one issuer's keys are never served for another
// and a rotation is seen within the TTL. Production verifiers should mirror
// the well-known file locally rather than fetch on every verify.

export const DEFAULT_KEYS_URL =
  'https://tunnelmind.ai/.well-known/receipt-signing-key.json';

export type AttestationStrength =
  | 'self-asserted'
  | 'software'
  | 'tee-tpm'
  | 'silicon-root';

export interface SigningKeyEntry {
  key_id: string;
  algorithm: 'Ed25519';
  public_key: string; // base64 raw 32-byte Ed25519
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

// Keyed by URL so one issuer's bundle is never served for another; entries
// expire so a rotated key is picked up within the TTL.
export const KEY_BUNDLE_CACHE_TTL_MS = 5 * 60 * 1000;
const _cache = new Map<string, { bundle: KeyBundle; fetchedAt: number }>();

export interface ResolveKeyOptions {
  /** Override the well-known URL (e.g., for self-hosted issuers). */
  url?: string;
  /** If true, bypass the in-memory cache and re-fetch. */
  noCache?: boolean;
  /** Max age of a cached bundle; default KEY_BUNDLE_CACHE_TTL_MS. */
  ttlMs?: number;
  /** Provide a pre-fetched bundle (skip network entirely). */
  bundle?: KeyBundle;
  /** Custom fetch (e.g., for offline tests). */
  fetcher?: typeof fetch;
}

/** The bundle at `opts.url` (default DEFAULT_KEYS_URL), from cache when fresh.
 *  Throws on a non-2xx status, a non-JSON body or a body without a `keys`
 *  array; the caller turns that into a verification error (fail closed). */
export async function fetchKeyBundle(opts: ResolveKeyOptions = {}): Promise<KeyBundle> {
  if (opts.bundle) return opts.bundle;
  const url = opts.url ?? DEFAULT_KEYS_URL;
  const hit = _cache.get(url);
  if (!opts.noCache && hit && Date.now() - hit.fetchedAt < (opts.ttlMs ?? KEY_BUNDLE_CACHE_TTL_MS)) return hit.bundle;
  const f = opts.fetcher ?? fetch;
  const r = await f(url);
  if (!r.ok) throw new Error(`fetchKeyBundle: ${url} returned ${r.status}`);
  const j = (await r.json()) as KeyBundle;
  if (!j || !Array.isArray(j.keys)) {
    throw new Error('fetchKeyBundle: response missing `keys` array');
  }
  _cache.set(url, { bundle: j, fetchedAt: Date.now() });
  return j;
}

/** The bundle entry named `keyId` (exact, case-sensitive match: key ids are
 *  opaque identifiers the issuer chose), or null. */
export function resolveKey(bundle: KeyBundle, keyId: string): SigningKeyEntry | null {
  return bundle.keys.find((k) => k.key_id === keyId) ?? null;
}

/** Reset the module-level key cache. Useful for tests + long-lived workers
 *  doing scheduled key refresh. */
export function clearKeyCache(): void {
  _cache.clear();
}

/** Why `entry` may not sign a receipt issued at `tsMs`, or null if it may.
 *  A usable key has status active or rotated (a missing status counts as
 *  active, so bare pinned/test bundles keep working) and a window
 *  [created_at, rotation_after] covering the timestamp; a missing bound is
 *  unbounded on that side; both bounds are inclusive. Past rotation_after is
 *  rejected even for a 'rotated' key: the window, not the status, says when
 *  it signed. An unparseable bound is a reason, not "unbounded" — a bundle
 *  typo must not widen a key's life. */
export function keyUsableAt(entry: SigningKeyEntry, tsMs: number): string | null {
  const status = entry.status ?? 'active';
  if (status !== 'active' && status !== 'rotated') {
    return `key ${entry.key_id} status is ${status}`;
  }
  if (entry.created_at !== undefined) {
    const from = Date.parse(entry.created_at);
    if (!Number.isFinite(from)) return `key ${entry.key_id} created_at is not a valid date`;
    if (tsMs < from) return `receipt timestamp precedes key ${entry.key_id} created_at ${entry.created_at}`;
  }
  if (entry.rotation_after !== undefined) {
    const until = Date.parse(entry.rotation_after);
    if (!Number.isFinite(until)) return `key ${entry.key_id} rotation_after is not a valid date`;
    if (tsMs > until) return `receipt timestamp is after key ${entry.key_id} rotation_after ${entry.rotation_after}`;
  }
  return null;
}
