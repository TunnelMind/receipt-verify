// V004 — the offline CLIs (scripts/verify-verdict.mjs, scripts/verify-log.mjs)
// trust only pinned keys, never keys carried in the receipt, STH or proof.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalizeBytes } from '../dist/jcs.js';
import { verifyReceipt } from '../scripts/verdict-lib/verify-receipt.js';
import { reconcile } from '../scripts/verdict-lib/reconcile.js';
import { leafHash as libLeafHash } from '../scripts/verdict-lib/log.js';
import { verifySth, verifyInclusion, leafHash, jcs } from '../scripts/verify-log.mjs';
import { makeReceipt, makeEphemeralKey, makeKeyBundle } from './_helpers.mjs';

const subtle = webcrypto.subtle;
const sign = async (kp, bytes) => Buffer.from(await subtle.sign('Ed25519', kp.privateKey, bytes)).toString('base64');

// A complete verdict receipt in the issuer's real shape (tunnelmind-data-api
// api/roots/log.js + verdict.js): the checkpoint carries NO signature; its root
// is signed only by the witness cosignature over canonical(checkpoint). The
// cosig ALSO embeds its public_key, the way an attacker would, so the tests
// prove embedded keys are ignored.
async function makeVerdict({ issuer, witness } = {}) {
  issuer ??= await makeEphemeralKey();
  witness ??= await makeEphemeralKey();
  const claim = { roots: [], best_verified_tier: 'self-asserted', key_control_proven: false };
  const payload = { claim, conduct: null, reconciliation: reconcile(claim, null) };
  const { receipt, keyId } = await makeReceipt({ payload, kp: issuer.kp, publicKeyB64: issuer.publicKeyB64 });
  const leaf = await libLeafHash(canonicalizeBytes(receipt));
  const checkpoint = { tree_id: 'test-log', tree_size: 1, root_hash: leaf, signed_at: new Date().toISOString() };
  receipt.self_verification = {
    inclusion_proof: { leaf_index: 0, tree_size: 1, audit_path: [] },
    checkpoint,
    witness_cosignatures: [{
      key_id: 'w1', public_key: witness.publicKeyB64, value: await sign(witness.kp, canonicalizeBytes(checkpoint)),
    }],
  };
  const keys = makeKeyBundle([{ key_id: keyId, algorithm: 'Ed25519', public_key: issuer.publicKeyB64 }]);
  return { receipt, keys, issuer, witness };
}

const check = (r, name) => r.checks.find((c) => c.check === name);

test('(a) self-signed verdict fails against the default pinned bundle', async () => {
  const v = await makeVerdict();
  const r = await verifyReceipt(v.receipt, { witnessKeys: [v.witness.publicKeyB64] });
  assert.equal(r.ok, false);
  assert.equal(check(r, 'receipt_signature').pass, false);
});

test('(a) self-signed verdict fails when its key_id is pinned with a different key', async () => {
  const v = await makeVerdict();
  const other = await makeEphemeralKey();
  const keys = makeKeyBundle([{ ...v.keys.keys[0], public_key: other.publicKeyB64 }]);
  const r = await verifyReceipt(v.receipt, { keys, witnessKeys: [v.witness.publicKeyB64] });
  assert.equal(check(r, 'receipt_signature').pass, false);
});

test('(b) positive control: same receipt passes with its keys pinned', async () => {
  const v = await makeVerdict();
  const r = await verifyReceipt(v.receipt, {
    keys: v.keys, witnessKeys: [{ key_id: 'w1', public_key: v.witness.publicKeyB64 }],
  });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
});

test('checkpoint: real-shape receipt passes on the pinned witness cosig alone, with no log key', async () => {
  const v = await makeVerdict();
  const r = await verifyReceipt(v.receipt, { keys: v.keys, witnessKeys: [v.witness.publicKeyB64] });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  assert.equal(check(r, 'checkpoint_signature'), undefined);
});

test('checkpoint: unpinned cosigner, no witness keys, or a tampered root_hash all fail', async () => {
  const v = await makeVerdict();
  const attacker = await makeEphemeralKey();
  let r = await verifyReceipt(v.receipt, { keys: v.keys, witnessKeys: [attacker.publicKeyB64] });
  assert.equal(check(r, 'witness_cosignatures').pass, false);
  assert.equal(r.ok, false);
  r = await verifyReceipt(v.receipt, { keys: v.keys });
  assert.equal(check(r, 'witness_cosignatures').pass, false);
  assert.equal(r.ok, false);
  v.receipt.self_verification.checkpoint.root_hash = 'ab'.repeat(32);
  r = await verifyReceipt(v.receipt, { keys: v.keys, witnessKeys: [v.witness.publicKeyB64] });
  assert.equal(check(r, 'witness_cosignatures').pass, false);
  assert.equal(r.ok, false);
});

test('checkpoint: a checkpoint that carries its own signature must verify against the pinned log key', async () => {
  const log = await makeEphemeralKey();
  const v = await makeVerdict();
  const sv = v.receipt.self_verification;
  const cpBody = sv.checkpoint;
  sv.checkpoint = {
    ...cpBody,
    signature: { algorithm: 'Ed25519', public_key: log.publicKeyB64, value: await sign(log.kp, canonicalizeBytes(cpBody)) },
  };
  // The cosig is over the checkpoint as published, signature included.
  sv.witness_cosignatures[0].value = await sign(v.witness.kp, canonicalizeBytes(sv.checkpoint));
  const base = { keys: v.keys, witnessKeys: [v.witness.publicKeyB64] };
  let r = await verifyReceipt(v.receipt, { ...base, logKey: log.publicKeyB64 });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  const attacker = await makeEphemeralKey();
  r = await verifyReceipt(v.receipt, { ...base, logKey: attacker.publicKeyB64 });
  assert.equal(check(r, 'checkpoint_signature').pass, false);
  assert.equal(r.ok, false);
  r = await verifyReceipt(v.receipt, base);
  assert.equal(check(r, 'checkpoint_signature').pass, false);
  assert.equal(r.ok, false);
});

test('(e) cosigs that verify only against their embedded public_key fail', async () => {
  const v = await makeVerdict();
  const pinnedWitness = await makeEphemeralKey();
  const opts = { keys: v.keys };
  let r = await verifyReceipt(v.receipt, { ...opts, witnessKeys: [pinnedWitness.publicKeyB64] });
  assert.equal(check(r, 'witness_cosignatures').pass, false);
  r = await verifyReceipt(v.receipt, opts);
  assert.equal(check(r, 'witness_cosignatures').pass, false);
  assert.equal(check(r, 'witness_cosignatures').detail, 'no pinned witness keys');
});

// ── verify-log.mjs ───────────────────────────────────────────────────────────

async function makeSth(signer, { root_hash, tree_size }) {
  const body = { tree_size, root_hash, timestamp: new Date().toISOString() };
  return {
    ...body,
    signature: { algorithm: 'Ed25519', public_key: signer.publicKeyB64, value: await sign(signer.kp, Buffer.from(jcs(body))) },
  };
}

test('(c) forged STH carrying the attacker key fails against the pinned log key', async () => {
  const pinned = await makeEphemeralKey();
  const attacker = await makeEphemeralKey();
  const forged = await makeSth(attacker, { root_hash: 'ab'.repeat(32), tree_size: 1 });
  assert.equal(verifySth(forged, pinned.publicKeyB64), false);
  const genuine = await makeSth(pinned, { root_hash: 'ab'.repeat(32), tree_size: 1 });
  assert.equal(verifySth(genuine, pinned.publicKeyB64), true);
});

test('(d) a lying proof leaf_hash does not help: the leaf comes from receipt bytes', async () => {
  const { receipt } = await makeVerdict();
  const { self_verification, ...bare } = receipt;
  const real = leafHash(Buffer.from(jcs(bare)));
  const liar = leafHash(Buffer.from('some other receipt'));
  // Proof root is the liar's leaf (1-leaf tree); it must not verify the real receipt.
  const root = liar;
  assert.equal(verifyInclusion({ leafIndex: 0, treeSize: 1, leaf: real, path: [], root }), false);
  assert.equal(verifyInclusion({ leafIndex: 0, treeSize: 1, leaf: liar, path: [], root }), true);
});

// ── CLI end to end ───────────────────────────────────────────────────────────

const run = (script, args) => {
  try { execFileSync(process.execPath, [script, ...args], { stdio: 'pipe' }); return 0; }
  catch (e) { return e.status; }
};

test('CLIs: self-signed verdict exits 1; inclusion needs a pinned key; forged STH and lying leaf_hash exit 1', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cli-test-'));
  const f = (name, obj) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(obj)); return p; };
  const v = await makeVerdict();
  const rPath = f('receipt.json', v.receipt);
  const flags = ['--witness-keys', v.witness.publicKeyB64];

  assert.equal(run('scripts/verify-verdict.mjs', [...flags, rPath]), 1);
  assert.equal(run('scripts/verify-verdict.mjs', ['--keys', f('keys.json', v.keys), ...flags, rPath]), 0);
  assert.equal(run('scripts/verify-verdict.mjs', ['--bogus', rPath]), 2);
  assert.equal(run('scripts/verify-verdict.mjs', []), 2);

  const root = leafHash(Buffer.from(jcs(v.receipt))).toString('hex');
  const proof = { leaf_index: 0, tree_size: 1, audit_path: [], root_hash: root, leaf_hash: root };
  const pinned = await makeEphemeralKey();
  const attacker = await makeEphemeralKey();
  const good = f('proof.json', { ...proof, sth: await makeSth(pinned, proof) });
  const forged = f('forged.json', { ...proof, sth: await makeSth(attacker, proof) });

  assert.equal(run('scripts/verify-log.mjs', ['inclusion', good, '--key', pinned.publicKeyB64, '--receipt', rPath]), 0);
  assert.equal(run('scripts/verify-log.mjs', ['inclusion', good, '--receipt', rPath]), 2);
  assert.equal(run('scripts/verify-log.mjs', ['inclusion', good, '--key', pinned.publicKeyB64]), 2);
  assert.equal(run('scripts/verify-log.mjs', ['inclusion', good, '--bogus', '--key', pinned.publicKeyB64, '--receipt', rPath]), 2);
  assert.equal(run('scripts/verify-log.mjs', ['inclusion', forged, '--key', pinned.publicKeyB64, '--receipt', rPath]), 1);

  // A proof whose leaf_hash/root describe some other receipt: honest STH, wrong leaf.
  const other = leafHash(Buffer.from('other')).toString('hex');
  const lying = { leaf_index: 0, tree_size: 1, audit_path: [], root_hash: other, leaf_hash: other };
  const lyingPath = f('lying.json', { ...lying, sth: await makeSth(pinned, lying) });
  assert.equal(run('scripts/verify-log.mjs', ['inclusion', lyingPath, '--key', pinned.publicKeyB64, '--receipt', rPath]), 1);
});

// R004 — the ledger leaf is JCS of the exact logged document, and verdict
// receipts are logged carrying self_verification. Nothing may be stripped.
test('CLI inclusion hashes the receipt as supplied, self_verification included', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cli-test-'));
  const f = (name, obj) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(obj)); return p; };
  const { receipt } = await makeVerdict();
  assert.ok(receipt.self_verification);
  const root = leafHash(Buffer.from(jcs(receipt))).toString('hex');
  const proof = { leaf_index: 0, tree_size: 1, audit_path: [], root_hash: root, leaf_hash: root };
  const pinned = await makeEphemeralKey();
  const proofPath = f('proof.json', { ...proof, sth: await makeSth(pinned, proof) });
  const { self_verification, ...bare } = receipt;
  const incl = (r) => run('scripts/verify-log.mjs', ['inclusion', proofPath, '--key', pinned.publicKeyB64, '--receipt', r]);
  assert.equal(incl(f('full.json', receipt)), 0);
  assert.equal(incl(f('bare.json', bare)), 1);
});
