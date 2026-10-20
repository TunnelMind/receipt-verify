// The frozen JCS wire vectors (test/vectors/jcs.json) against every
// canonicalizer this repo carries: the package, the vendored verdict kernel
// and the independent log verifier. tollbooth and atap carry byte-identical
// copies of the vector file; a change here must be mirrored there.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalize } from '../dist/jcs.js';
import { canonicalize as verdictCanonicalize } from '../scripts/verdict-lib/jcs.js';
import { jcs } from '../scripts/verify-log.mjs';

const { vectors } = JSON.parse(readFileSync(new URL('./vectors/jcs.json', import.meta.url), 'utf8'));

const impls = [
  ['src/jcs.ts', canonicalize],
  ['scripts/verdict-lib/jcs.js', verdictCanonicalize],
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
