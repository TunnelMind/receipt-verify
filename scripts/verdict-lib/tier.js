/**
 * verdict-lib/tier.js (from tunnelmind-data-api api/roots/tier.js)
 *
 * The attestation-tier ladder (ADR-001 invariant 4). One ordered scale that
 * every root normalizes onto, so the reconciliation layer can compare a claim
 * from any root against any other and against conduct.
 *
 *   self-asserted < software < tee-tpm < silicon-root
 *
 * A tier is ALWAYS measured/anchored, never taken from a claimant's say-so.
 * Only what reconcile() reads is here; the service file's isTier / maxTier /
 * capTier (root-verifier enforcement) had no caller in this repo and were
 * dropped 2026-10-21.
 */

// Ordered low → high. Index is the ordinal used for comparison + the claim-side
// trust mapping in reconcile().
export const TIER_LADDER = Object.freeze([
  'self-asserted',
  'software',
  'tee-tpm',
  'silicon-root',
]);

/** Ordinal of a tier (0..N-1), or -1 if not a known tier. */
export function tierOrdinal(tier) {
  return TIER_LADDER.indexOf(tier);
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
