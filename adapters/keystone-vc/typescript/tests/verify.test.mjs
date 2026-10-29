/**
 * Regression tests for the binding-field bypass.
 *
 * canonicalize() drops keys whose value is `undefined`. The verifier used to pass the field
 * straight through, so a payload that never carried it hashed to a reduced digest, and a claim
 * computed the same way compared equal — `true` for a document that asserted nothing.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

import { executionRef, toVerifiableCredential, verifyVcExecutionRef } from '../dist/index.js';

const sha = (o) => 'sha256:' + createHash('sha256').update(canonicalize(o)).digest('hex');
const DEC = 'sha256:' + 'a'.repeat(64);
const BASE = { decisionRef: DEC, actionType: 'transfer', scope: 'bilateral', outcome: 'COMMITTED', executedAtMs: 1716460800000, issuer: 'did:web:algovoi.co.uk', issuedAtMs: 1716460800000 };

test('a genuine credential verifies', () => {
  assert.equal(verifyVcExecutionRef(toVerifiableCredential(BASE)), true);
});

test('a credential whose binding field is ABSENT is rejected', () => {
  const reduced = { actionType: 'transfer', scope: 'bilateral', outcome: 'COMMITTED', executedAtMs: 1716460800000 };
  const forged = sha(reduced);
  const vc = { credentialSubject: { ...reduced, executionRef: forged, id: forged } };
  assert.equal(verifyVcExecutionRef(vc), false, 'must not verify a subject missing decisionRef');
});

test('a tampered credential is rejected', () => {
  const vc = toVerifiableCredential(BASE);
  vc.credentialSubject.outcome = 'DECLINED';
  assert.equal(verifyVcExecutionRef(vc), false);
});

test('a missing or non-string claim is rejected', () => {
  assert.equal(verifyVcExecutionRef({}), false);
  assert.equal(verifyVcExecutionRef({ credentialSubject: {} }), false);
  assert.equal(verifyVcExecutionRef(null), false);
});

test('executionRef refuses an absent binding field', () => {
  for (const idx of [0, 1, 2, 3]) {
    const args = ['sha256:x', 'transfer', 'bilateral', 'COMMITTED', 1];
    args[idx] = undefined;
    assert.throws(() => executionRef(...args), /must be a non-empty string/);
  }
});
