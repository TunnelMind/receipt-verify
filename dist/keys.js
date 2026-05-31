// Receipt signing-key bundle resolution. Spec §4 step 2: relying parties
// fetch the well-known bundle, find the key whose key_id matches the
// receipt's, and confirm its public_key equals the receipt's.
//
// This module fetches once per process and caches; pass `noCache: true`
// to force a re-fetch. Production verifiers should mirror the well-known
// feed locally rather than hitting the network on every verify.
export const DEFAULT_KEYS_URL = 'https://tunnelmind.ai/.well-known/receipt-signing-key.json';
let _cache = null;
export async function fetchKeyBundle(opts = {}) {
    if (opts.bundle)
        return opts.bundle;
    if (!opts.noCache && _cache)
        return _cache.bundle;
    const url = opts.url ?? DEFAULT_KEYS_URL;
    const f = opts.fetcher ?? fetch;
    const r = await f(url);
    if (!r.ok)
        throw new Error(`fetchKeyBundle: ${url} returned ${r.status}`);
    const j = (await r.json());
    if (!j || !Array.isArray(j.keys)) {
        throw new Error('fetchKeyBundle: response missing `keys` array');
    }
    _cache = { bundle: j, fetchedAt: Date.now() };
    return j;
}
export function resolveKey(bundle, keyId) {
    return bundle.keys.find((k) => k.key_id === keyId) ?? null;
}
/** Reset the module-level key cache. Useful for tests + long-lived workers
 *  doing scheduled key refresh. */
export function clearKeyCache() {
    _cache = null;
}
//# sourceMappingURL=keys.js.map