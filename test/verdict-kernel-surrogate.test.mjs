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
