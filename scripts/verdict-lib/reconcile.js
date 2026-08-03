/**
 * api/roots/reconcile.js
 *
 * Phase 2.2 — RECONCILE (pure). Given the claim side (what the key proves about
 * itself, from translateClaims) and the conduct side (what the graph has seen),
 * compute the contradictions, the claim-vs-conduct delta, and the verdict.
 *
 * Pure + dependency-light (tier.js only) on purpose: the standalone offline
 * verifier (scripts/verify-verdict.mjs) imports THIS exact function to re-derive
 * a published verdict from receipt bytes, with no service or network in scope
 * (ADR-001 invariant 5). Keep it that way — no fetch, no env, no Worker bindings.
 */

import { tierClaimWeight, tierOrdinal } from './tier.js';

// A claim that trusts itself more than conduct supports by this much is an
// over-claim: e.g. a verified silicon-root EAT (claim weight 1.0) whose observed
// conduct trust is 0.30 → delta 0.70. The reconciliation signal no single root
// can produce on its own.
export const OVERCLAIM_DELTA = 0.35;

/**
 * @param {object} claimSide — translateClaims() output
 *   { roots:[{root,tier,verified,props}], best_verified_tier, key_control_proven }
 * @param {object|null} conduct — { trust_score, confidence, observed } | null
 * @returns {{contradictions:Array, claim_vs_conduct_delta:number|null,
 *            verdict:{tier,reputation,flags,confidence}}}
 */
export function reconcile(claimSide, conduct) {
  const contradictions = [];
  const flags = [];

  const tier = claimSide.best_verified_tier;
  const claimTrust = tierClaimWeight(tier);

  // A presented-but-failed claim is a contradiction; an absent claim is not.
  let anyPresented = false;
  for (const r of claimSide.roots) {
    const reason = r.props && r.props.reason;
    const wasPresented = r.verified || (reason && !/^no_.*_presented$/.test(reason));
    if (wasPresented) anyPresented = true;
    if (!r.verified && reason && !/^no_.*_presented$/.test(reason) && reason !== 'malformed_self_claim') {
      contradictions.push({ type: 'unverified_claim', root: r.root, reason });
    }
  }

  if (anyPresented && !claimSide.key_control_proven) {
    contradictions.push({
      type: 'key_control_unproven',
      detail: 'a claim was presented but no root cryptographically proved control of this key',
    });
    flags.push('key_control_unproven');
  }

  const conductTrust = conduct && Number.isFinite(conduct.trust_score) ? conduct.trust_score : null;
  let delta = null;
  if (conductTrust !== null) {
    delta = Number((claimTrust - conductTrust).toFixed(4));
    if (delta >= OVERCLAIM_DELTA && tierOrdinal(tier) >= tierOrdinal('software')) {
      contradictions.push({
        type: 'claim_exceeds_conduct',
        claim_trust: claimTrust, conduct_trust: conductTrust, delta,
        detail: `key attests ${tier} but observed conduct trust is ${conductTrust}`,
      });
      flags.push('over_claim');
    } else if (delta <= -OVERCLAIM_DELTA) {
      flags.push('under_claim'); // behaves better than it attests — informational
    }
  } else {
    flags.push('no_conduct_data');
  }

  if (claimSide.key_control_proven) flags.push('key_control_proven');
  if (tierOrdinal(tier) >= tierOrdinal('tee-tpm')) flags.push('hardware_rooted');

  // reputation = observed conduct trust; never manufactured from absence.
  const reputation = conductTrust;

  let confidence;
  if (!claimSide.key_control_proven && conductTrust === null) confidence = 0.0;
  else if (claimSide.key_control_proven && conductTrust !== null) {
    confidence = Math.min(0.96, 0.6 + (conduct.confidence || 0) * 0.4);
  } else {
    confidence = 0.5; // one side only
  }

  return {
    contradictions,
    claim_vs_conduct_delta: delta,
    verdict: { tier, reputation, flags, confidence: Number(confidence.toFixed(4)) },
  };
}
