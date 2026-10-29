/**
 * Regression tests for the binding-field bypass.
 *
 * canonicalize() drops keys whose value is `undefined`. The verifier used to pass
 * `d.decision_ref` straight through, so a payload that never carried the field hashed to a
 * reduced digest, and a claim computed the same way compared equal — `true` for a document
 * that asserted nothing. These tests pin the fail-closed behaviour.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import canonicalize from 'canonicalize';
import { createHash } from 'node:crypto';

import { executionRef, toCloudEvent, verifyCloudEventExecutionRef } from '../dist/index.js';

const sha = (o) => 'sha256:' + createHash('sha256').update(canonicalize(o)).digest('hex');

const DEC = 'sha256:' + 'a'.repeat(64);
const BASE = { decisionRef: DEC, actionType: 'transfer', scope: 'bilateral', outcome: 'COMMITTED', executedAtMs: 1716460800000, source: 'agent' };

test('a genuine event verifies', () => {
  assert.equal(verifyCloudEventExecutionRef(toCloudEvent(BASE)), true);
});

test('an event whose binding field is ABSENT is rejected', () => {
  // the exact payload the old code accepted: no decision_ref, claim over the reduced preimage
  const reduced = { action_type: 'transfer', scope: 'bilateral', outcome: 'COMMITTED', executed_at_ms: 1716460800000 };
  const forged = sha(reduced);
  const ev = { data: { ...reduced, execution_ref: forged } };
  assert.equal(verifyCloudEventExecutionRef(ev), false, 'must not verify a document missing decision_ref');
});

test('a tampered event is still rejected', () => {
  const ev = toCloudEvent(BASE);
  ev.data.outcome = 'DECLINED';
  assert.equal(verifyCloudEventExecutionRef(ev), false);
});

test('a missing or non-string claim is rejected', () => {
  assert.equal(verifyCloudEventExecutionRef({ data: {} }), false);
  assert.equal(verifyCloudEventExecutionRef({ data: { execution_ref: 42 } }), false);
  assert.equal(verifyCloudEventExecutionRef({}), false);
  assert.equal(verifyCloudEventExecutionRef(null), false);
});

test('executionRef refuses an absent binding field rather than hashing a reduced payload', () => {
  for (const idx of [0, 1, 2, 3]) {
    const args = ['sha256:x', 'transfer', 'bilateral', 'COMMITTED', 1];
    args[idx] = undefined;
    assert.throws(() => executionRef(...args), /must be a non-empty string/);
  }
  assert.throws(() => executionRef('sha256:x', 'transfer', 'bilateral', 'COMMITTED', NaN), /finite number/);
});
