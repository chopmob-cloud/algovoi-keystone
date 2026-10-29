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

import { executionRef, verifyExecutionRef } from '../dist/index.js';

const DEC = 'sha256:' + 'a'.repeat(64);

test('a genuine ref verifies', () => {
  const ref = executionRef(DEC, 'transfer', 'bilateral', 'COMMITTED', 1716460800000);
  assert.equal(verifyExecutionRef(DEC, 'transfer', 'bilateral', 'COMMITTED', 1716460800000, ref).ok, true);
});

test('absent or non-string arguments are rejected rather than hashed', () => {
  const ref = executionRef(DEC, 'transfer', 'bilateral', 'COMMITTED', 1716460800000);
  assert.equal(verifyExecutionRef(undefined, 'transfer', 'bilateral', 'COMMITTED', 1716460800000, ref).ok, false);
  assert.equal(verifyExecutionRef(DEC, 'transfer', 'bilateral', 'COMMITTED', 1716460800000, undefined).ok, false);
  assert.equal(verifyExecutionRef(DEC, 'transfer', 'bilateral', 'COMMITTED', 1716460800000, 42).ok, false);
});

test('a wrong claim is rejected', () => {
  assert.equal(verifyExecutionRef(DEC, 'transfer', 'bilateral', 'DECLINED', 1716460800000,
                                  'sha256:' + 'b'.repeat(64)).ok, false);
});
