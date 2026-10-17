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
 * Given a reconciliation receipt's bytes + PINNED issuer, log and witness public
 * keys (never keys carried inside the receipt), re-derive and check the verdict
 * with NO call to TunnelMind. The actual
 * checks live in api/roots/verify-receipt.js (pure, importable, also unit-tested);
 * this file is only argv/IO around it. That module imports the SAME reconcile()
 * and Merkle verifier the service runs — the verifier IS the spec.
 *
 * Usage:
 *   node scripts/verify-verdict.mjs [--keys <bundle.json>] --log-key <b64> \
 *     --witness-keys <keys.json | b64,b64,…> <receipt.json>
 *   curl -s https://data.tunnelmind.ai/v1/verdict/<key>?subject=<d> \
 *     | node scripts/verify-verdict.mjs --log-key <b64> --witness-keys <…> -
 *
 *   --keys          issuer KeyBundle JSON; default = the bundle shipped in
 *                   dist/pinned-keys.js (run `npm run build` first)
 *   --log-key       base64 raw Ed25519 key that signs log checkpoints
 *   --witness-keys  JSON file (array of b64 keys or {key_id, public_key}) or a
 *                   comma-separated list of b64 keys
 * Without --log-key / --witness-keys those checks FAIL: there is nothing
 * pinned to verify them against.
 *
 * Exit 0 = all checks pass; 1 = a check failed; 2 = bad usage.
 */

import { readFileSync, existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { verifyReceipt } from './verdict-lib/verify-receipt.js';

const USAGE = 'usage: node scripts/verify-verdict.mjs [--keys <bundle.json>] [--log-key <b64>]'
  + ' [--witness-keys <file.json | b64,b64>] <receipt.json | ->';
const usage = (why) => { console.error(`${why ? why + '\n' : ''}${USAGE}`); process.exit(2); };

async function main() {
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({
      options: { keys: { type: 'string' }, 'log-key': { type: 'string' }, 'witness-keys': { type: 'string' } },
      allowPositionals: true,
    }));
  } catch (e) { usage(e.message); }
  const arg = positionals[0];
  if (!arg || positionals.length > 1) usage();

  const opts = { logKey: values['log-key'] };
  if (values.keys) {
    opts.keys = JSON.parse(readFileSync(values.keys, 'utf8'));
    if (!opts.keys || !Array.isArray(opts.keys.keys)) usage(`--keys ${values.keys}: not a key bundle (no keys array)`);
  }
  const wk = values['witness-keys'];
  if (wk) opts.witnessKeys = existsSync(wk) ? JSON.parse(readFileSync(wk, 'utf8')) : wk.split(',').filter(Boolean);
  if (wk && !Array.isArray(opts.witnessKeys)) usage(`--witness-keys ${wk}: expected a JSON array`);

  const text = arg === '-' ? readFileSync(0, 'utf8') : readFileSync(arg, 'utf8');
  let obj = JSON.parse(text);
  // Accept a bare receipt, a { receipt }, or the full /v1/verdict response.
  if (obj.data && obj.data.receipt) obj = obj.data.receipt;
  else if (obj.receipt) obj = obj.receipt;

  const { ok, checks } = await verifyReceipt(obj, opts);
  for (const c of checks) {
    console.log(`${c.pass ? 'PASS' : 'FAIL'}  ${c.check}${c.detail ? '  — ' + c.detail : ''}`);
  }
  console.log(ok ? '\nOK: verdict verifies offline.' : '\nFAILED: verdict did not verify.');
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error('verifier error:', e.message); process.exit(1); });
