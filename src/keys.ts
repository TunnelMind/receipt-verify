// Receipt signing-key bundle resolution. Spec §4 step 2: relying parties
// fetch the well-known bundle, find the key whose key_id matches the
// receipt's, and confirm its public_key equals the receipt's.
//
// This module fetches once per process and caches; pass `noCache: true`
// to force a re-fetch. Production verifiers should mirror the well-known
// feed locally rather than hitting the network on every verify.

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

let _cache: { bundle: KeyBundle; fetchedAt: number } | null = null;

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

export async function fetchKeyBundle(opts: ResolveKeyOptions = {}): Promise<KeyBundle> {
  if (opts.bundle) return opts.bundle;
  if (!opts.noCache && _cache) return _cache.bundle;
  const url = opts.url ?? DEFAULT_KEYS_URL;
  const f = opts.fetcher ?? fetch;
  const r = await f(url);
  if (!r.ok) throw new Error(`fetchKeyBundle: ${url} returned ${r.status}`);
  const j = (await r.json()) as KeyBundle;
  if (!j || !Array.isArray(j.keys)) {
    throw new Error('fetchKeyBundle: response missing `keys` array');
  }
  _cache = { bundle: j, fetchedAt: Date.now() };
  return j;
}

export function resolveKey(bundle: KeyBundle, keyId: string): SigningKeyEntry | null {
  return bundle.keys.find((k) => k.key_id === keyId) ?? null;
}

/** Reset the module-level key cache. Useful for tests + long-lived workers
 *  doing scheduled key refresh. */
export function clearKeyCache(): void {
  _cache = null;
}
