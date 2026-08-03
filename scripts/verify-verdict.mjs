#!/usr/bin/env node
// Moved here 2026-08-02 from tunnelmind-data-api/scripts/verify-verdict.mjs
// (research-house shift follow-up): the standalone verdict verifier and its
// pure dependency chain (scripts/verdict-lib/) are public kernel material —
// the site has always claimed the reconciliation core and offline verifier
// are open. Byte-identical to the originals except import paths.
/**
 * scripts/verify-verdict.mjs
 *
 * Phase 2.3 — the STANDALONE, OFFLINE verdict verifier CLI (ADR-001 invariant 5).
 *
 * Given a reconciliation receipt's bytes + the witness public keys carried INSIDE
 * it, re-derive and check the verdict with NO call to TunnelMind. The actual
 * checks live in api/roots/verify-receipt.js (pure, importable, also unit-tested);
 * this file is only argv/IO around it. That module imports the SAME reconcile()
 * and Merkle verifier the service runs — the verifier IS the spec.
 *
 * Usage:
 *   node scripts/verify-verdict.mjs <receipt.json>
 *   curl -s https://data.tunnelmind.ai/v1/verdict/<key>?subject=<d> \
 *     | node scripts/verify-verdict.mjs -
 *
 * Exit 0 = all checks pass; 1 = a check failed; 2 = bad usage.
 */

import { readFileSync } from 'node:fs';
import { verifyReceipt } from './verdict-lib/verify-receipt.js';

async function main() {
  const arg = process.argv[2];
  if (!arg) {
    console.error('usage: node scripts/verify-verdict.mjs <receipt.json | ->');
    process.exit(2);
  }
  const text = arg === '-' ? readFileSync(0, 'utf8') : readFileSync(arg, 'utf8');
  let obj = JSON.parse(text);
  // Accept a bare receipt, a { receipt }, or the full /v1/verdict response.
  if (obj.data && obj.data.receipt) obj = obj.data.receipt;
  else if (obj.receipt) obj = obj.receipt;

  const { ok, checks } = await verifyReceipt(obj);
  for (const c of checks) {
    console.log(`${c.pass ? 'PASS' : 'FAIL'}  ${c.check}${c.detail ? '  — ' + c.detail : ''}`);
  }
  console.log(ok ? '\nOK: verdict verifies offline.' : '\nFAILED: verdict did not verify.');
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error('verifier error:', e.message); process.exit(1); });
