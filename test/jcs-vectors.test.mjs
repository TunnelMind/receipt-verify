// The frozen JCS wire vectors (test/vectors/jcs.json) against every
// canonicalizer entry point this repo carries: the package, the verdict
// kernel (a re-export of the package's, pinned below by identity) and the
// independent log verifier. Fareseal and atap vendor the vector
// file verbatim; a change here must be mirrored there.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalize } from '../dist/jcs.js';
import * as distIndex from '../dist/index.js';
import * as verdictLib from '../scripts/verdict-lib/jcs.js';
import { jcs } from '../scripts/verify-log.mjs';

const { vectors } = JSON.parse(readFileSync(new URL('./vectors/jcs.json', import.meta.url), 'utf8'));

const impls = [
  ['src/jcs.ts', canonicalize],
  ['scripts/verdict-lib/jcs.js', verdictLib.canonicalize],
  ['scripts/verify-log.mjs jcs()', jcs],
];

for (const [name, fn] of impls) {
  for (const v of vectors) {
    test(`${name}: ${v.name}`, () => {
      if (v.throws) assert.throws(() => fn(v.input), /lone surrogate/);
      else assert.equal(fn(v.input), v.canonical);
    });
  }
}

// The verdict kernel must not grow its own copy again: same function objects.
test('scripts/verdict-lib/jcs.js re-exports the package canonicalizer', () => {
  assert.ok(verdictLib.canonicalize === distIndex.canonicalize);
  assert.ok(verdictLib.canonicalizeBytes === distIndex.canonicalizeBytes);
});
