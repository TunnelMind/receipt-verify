// Review 2026-10-20 C1: the verdict kernel reports per check and never throws,
// even when the receipt carries a lone surrogate the canonicalizer refuses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyReceipt } from '../scripts/verdict-lib/verify-receipt.js';

test('kernel: a lone surrogate in the payload is a failed check, not a throw', async () => {
  const receipt = {
    receipt_id: 'r', timestamp: '2026-10-20T00:00:00Z', payload: { roots: ['\ud800'] },
    payload_hash: '0x00', signature: { algorithm: 'Ed25519', key_id: 'none', value: 'AA==' },
    self_verification: { inclusion_proof: { leaf_index: 0, tree_size: 1, audit_path: [] }, checkpoint: { root_hash: '0x00' } },
  };
  const out = await verifyReceipt(receipt, { keys: { keys: [] } });
  assert.equal(out.ok, false);
  const byName = Object.fromEntries(out.checks.map((c) => [c.check, c]));
  assert.match(byName.payload_hash.detail, /lone surrogate/);
  assert.match(byName.log_inclusion.detail, /lone surrogate/);
});

// 2026-10-21: the same rule for a cosig entry that is not an object and a
// claim.roots reconcile() cannot iterate — failed checks, no throw.
test('kernel: garbage cosigs and an un-iterable claim.roots are failed checks, not throws', async () => {
  const receipt = {
    receipt_id: 'r', timestamp: '2026-10-20T00:00:00Z',
    payload: { claim: { roots: 5, best_verified_tier: 'software', key_control_proven: true }, reconciliation: {} },
    payload_hash: '0x00', signature: { algorithm: 'Ed25519', key_id: 'none', value: 'AA==' },
    self_verification: {
      inclusion_proof: { leaf_index: 0, tree_size: 1, audit_path: [] },
      checkpoint: { root_hash: '0x00' },
      witness_cosignatures: [null, 'not a cosig', 7],
    },
  };
  const out = await verifyReceipt(receipt, { keys: { keys: [] }, witnessKeys: ['AA=='] });
  assert.equal(out.ok, false);
  const byName = Object.fromEntries(out.checks.map((c) => [c.check, c]));
  assert.equal(byName.witness_cosignatures.pass, false);
  assert.equal(byName.witness_cosignatures.detail, 'none present');
  assert.equal(byName.verdict_rederivation.pass, false);
  assert.match(byName.verdict_rederivation.detail, /not iterable/);
});
