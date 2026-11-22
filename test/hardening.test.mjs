// Review hardening for 4.0.0 (receipt-verify#8, Fable second review):
// frozen trust roots, a verifyReceipt that never throws, and a proof fetch
// that is bounded in time and size and refuses a bad endpoint.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyReceipt,
  fetchInclusionProof,
  LogProofUnavailable,
  PINNED_KEY_BUNDLE,
  PINNED_LOG_KEYS,
  MAX_LOG_PROOF_BYTES,
} from '../dist/index.js';

const ID = 'r-0123456789';

function deepFrozen(o) {
  if (!o || typeof o !== 'object') return true;
  return Object.isFrozen(o) && Object.values(o).every(deepFrozen);
}

test('the pinned trust roots cannot be edited through the export', () => {
  assert.ok(deepFrozen(PINNED_KEY_BUNDLE));
  assert.ok(deepFrozen(PINNED_LOG_KEYS));
  assert.throws(() => PINNED_KEY_BUNDLE.keys.push({ key_id: 'evil' }), TypeError);
  assert.throws(() => { PINNED_LOG_KEYS.keys[0].public_key = 'x'; }, TypeError);
});

test('verifyReceipt never throws, even on a payload too deep to walk', async () => {
  let deep = 0;
  for (let i = 0; i < 6000; i++) deep = [deep];
  const r = await verifyReceipt({ receipt_version: '1.0', receipt_id: ID, payload: deep, signature: { key_id: 'k', public_key: 'x', value: 'x' } });
  assert.equal(r.valid, false);
  assert.match(r.errors.join(';'), /could not be checked|canonicalization failed/);
});

const expectUnavailable = async (p, want) => {
  await assert.rejects(p, (e) => e instanceof LogProofUnavailable && e.kind === 'unavailable' && want.test(e.message));
};

test('fetchInclusionProof refuses a bad endpoint before any request', async () => {
  let calls = 0;
  const fetcher = async () => { calls++; return new Response('{}'); };
  await expectUnavailable(fetchInclusionProof(ID, { url: 'nope', fetcher }), /not a URL/);
  for (const url of ['http://data.example/proof', 'file:///etc/passwd', 'https://u:p@data.example/proof']) {
    await expectUnavailable(fetchInclusionProof(ID, { url, fetcher }), /must be https/);
  }
  assert.equal(calls, 0);
});

test('fetchInclusionProof gives up after timeoutMs, even if the fetcher ignores the signal', { timeout: 5000 }, async () => {
  let signal;
  const hang = (_u, init) => { signal = init?.signal; return new Promise(() => {}); };
  const t0 = Date.now();
  await expectUnavailable(fetchInclusionProof(ID, { fetcher: hang, timeoutMs: 50 }), /no answer from .* in 50 ms/);
  assert.ok(Date.now() - t0 < 2000);
  assert.equal(signal?.aborted, true);
});

test('fetchInclusionProof reads no more than MAX_LOG_PROOF_BYTES', async () => {
  const big = 'x'.repeat(MAX_LOG_PROOF_BYTES + 1);
  // Declared too large.
  const declared = async () => new Response(big, { headers: { 'content-length': String(big.length) } });
  await expectUnavailable(fetchInclusionProof(ID, { fetcher: declared }), /over \d+ bytes/);
  // Streamed with no length.
  const streamed = async () => new Response(new ReadableStream({
    pull(c) { c.enqueue(new TextEncoder().encode('x'.repeat(16 * 1024))); },
  }));
  await expectUnavailable(fetchInclusionProof(ID, { fetcher: streamed }), /over \d+ bytes/);
});
