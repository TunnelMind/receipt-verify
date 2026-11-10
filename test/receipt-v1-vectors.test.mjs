// The Receipt v1.0 vectors shared with the Rust verifier (rune-record):
// each raw file through verifyReceiptJson with the manifest's keys and
// revocations must give its expected verdict, and every invalid case exactly
// one error. Regenerate with scripts/gen-receipt-v1-vectors.mjs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyReceiptJson } from '../dist/index.js';

const DIR = new URL('./vectors/receipt-v1/', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('cases.json', DIR), 'utf8'));

// Error string → verdict name, matched against the verifier's exact messages.
const VERDICTS = [
  ['unknown_key',        /not present in key bundle/],
  ['expired_key',        /rotation_after/],
  ['revoked_key',        /^signing key \S+ revoked at /],
  ['tier_too_high',      /ceiling violated/],
  ['missing_public_key', /^signature\.public_key: required/],
  ['missing_receipt_id', /^receipt_id: required/],
  ['float_payload',      /not a JS-safe integer/],
  ['duplicate_key',      /^duplicate key /],
  ['bad_timestamp',      /^timestamp: not a valid date/],
];

test('cases.json lists the 10 named cases', () => {
  assert.deepEqual(manifest.cases.map((c) => c.name), [
    'valid', 'unknown_key', 'expired_key', 'revoked_key', 'tier_too_high', 'missing_public_key',
    'missing_receipt_id', 'float_payload', 'duplicate_key', 'bad_timestamp',
  ]);
});

for (const c of manifest.cases) {
  test(`receipt-v1 vector ${c.name}`, async () => {
    const text = readFileSync(new URL(c.file, DIR), 'utf8');
    const r = await verifyReceiptJson(text, {
      keys: manifest.keys, revocations: manifest.revocations, noFetchKeys: true,
    });
    const name = r.valid ? 'valid'
      : VERDICTS.find(([, re]) => r.errors.some((e) => re.test(e)))?.[0] ?? `unmapped: ${r.errors.join('; ')}`;
    assert.equal(name, c.expect, JSON.stringify(r.errors));
    if (c.expect !== 'valid') assert.equal(r.errors.length, 1, JSON.stringify(r.errors));
    else assert.deepEqual(r.errors, []);
  });
}
