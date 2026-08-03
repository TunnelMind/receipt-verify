/**
 * api/roots/tier.js
 *
 * The attestation-tier ladder (ADR-001 invariant 4). One ordered scale that
 * every root normalizes onto, so the reconciliation layer can compare a claim
 * from any root against any other and against conduct.
 *
 *   self-asserted < software < tee-tpm < silicon-root
 *
 * A tier is ALWAYS measured/anchored, never taken from a claimant's say-so.
 * The helpers here are pure; enforcement (capping a token's claimed tier at
 * what its trust anchor is trusted to assert) lives in the root verifiers.
 */

// Ordered low → high. Index is the ordinal used for comparison + the claim-side
// trust mapping in reconcile().
export const TIER_LADDER = Object.freeze([
  'self-asserted',
  'software',
  'tee-tpm',
  'silicon-root',
]);

export const LOWEST_TIER  = TIER_LADDER[0];
export const HIGHEST_TIER = TIER_LADDER[TIER_LADDER.length - 1];

/** Ordinal of a tier (0..N-1), or -1 if not a known tier. */
export function tierOrdinal(tier) {
  return TIER_LADDER.indexOf(tier);
}

/** True when `tier` is one of the canonical ladder values. */
export function isTier(tier) {
  return tierOrdinal(tier) >= 0;
}

/**
 * The higher of two tiers (by ordinal). Unknown tiers are treated as below the
 * floor so they never win. Used to fold many verified roots into one best tier.
 */
export function maxTier(a, b) {
  return tierOrdinal(a) >= tierOrdinal(b) ? (isTier(a) ? a : LOWEST_TIER)
                                          : (isTier(b) ? b : LOWEST_TIER);
}

/**
 * Cap a claimed tier at the maximum a trust anchor is trusted to assert.
 * Invariant 4 in code: a token may *say* silicon-root, but if the anchor that
 * signed it is only trusted to `software`, the measured tier is `software`.
 */
export function capTier(claimed, anchorMax) {
  const c = isTier(claimed)   ? tierOrdinal(claimed)   : -1;
  const m = isTier(anchorMax) ? tierOrdinal(anchorMax) : tierOrdinal(LOWEST_TIER);
  if (c < 0) return LOWEST_TIER;
  return TIER_LADDER[Math.min(c, m)];
}

/**
 * Map a tier to a [0,1] claim-side trust weight — "how much should the actor's
 * own assertion count before we look at conduct." A self-asserted key proves
 * only key control (0.50 floor); silicon-root proves a hardware-rooted identity
 * (1.0). These are the priors reconcile() blends with observed conduct.
 */
export function tierClaimWeight(tier) {
  switch (tier) {
    case 'silicon-root': return 1.00;
    case 'tee-tpm':      return 0.85;
    case 'software':     return 0.65;
    case 'self-asserted':return 0.50;
    default:             return 0.50;
  }
}
