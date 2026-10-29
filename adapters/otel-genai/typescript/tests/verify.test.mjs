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

import { executionRef, toGenAiAttributes, verifyGenAiExecutionRef } from '../dist/index.js';

const sha = (o) => 'sha256:' + createHash('sha256').update(canonicalize(o)).digest('hex');
const DEC = 'sha256:' + 'a'.repeat(64);
const BASE = { decisionRef: DEC, actionType: 'transfer', scope: 'bilateral', outcome: 'COMMITTED', executedAtMs: 1716460800000 };

test('genuine attributes verify', () => {
  assert.equal(verifyGenAiExecutionRef(toGenAiAttributes(BASE)), true);
});

test('attributes whose binding field is ABSENT are rejected', () => {
  const reduced = { 'algovoi.keystone.action_type': 'transfer', 'algovoi.keystone.scope': 'bilateral',
                    'algovoi.keystone.outcome': 'COMMITTED', 'algovoi.keystone.executed_at_ms': 1716460800000 };
  const forged = sha({ action_type: 'transfer', scope: 'bilateral', outcome: 'COMMITTED', executed_at_ms: 1716460800000 });
  assert.equal(verifyGenAiExecutionRef({ ...reduced, 'algovoi.keystone.execution_ref': forged }), false,
               'must not verify attributes missing decision_ref');
});

test('a tampered span is rejected', () => {
  const attrs = toGenAiAttributes(BASE);
  attrs['algovoi.keystone.outcome'] = 'DECLINED';
  assert.equal(verifyGenAiExecutionRef(attrs), false);
});

test('a missing or non-string claim is rejected', () => {
  assert.equal(verifyGenAiExecutionRef({}), false);
  assert.equal(verifyGenAiExecutionRef(null), false);
});

test('executionRef refuses an absent binding field', () => {
  for (const idx of [0, 1, 2, 3]) {
    const args = ['sha256:x', 'transfer', 'bilateral', 'COMMITTED', 1];
    args[idx] = undefined;
    assert.throws(() => executionRef(...args), /must be a non-empty string/);
  }
});
