# algovoi-delegation-ref

**Content-addressed delegation references** for the AlgoVoi substrate. An agent
delegates authority to another agent for a scope and a validity window; the
`delegation_ref` is the content hash of that delegation envelope, so any tamper
(widening the scope, extending the expiry, swapping the delegate) changes the ref
and is detectable offline. Delegations chain (A→B→C) via `prev_delegation_ref`,
giving a tamper-evident delegation chain.

This is the inverse of an **opaque** delegation token (an arbitrary label that does
not change when the delegation's content is altered). Additive over the frozen
substrate (Apache-2.0); no new cryptography:

```
delegation_ref = "sha256:" + SHA-256(JCS(RFC 8785)({
    delegate_id, delegator_id, not_after_ms, not_before_ms,
    prev_delegation_ref, scope }))
```

with **integer-millisecond** validity bounds.

## Install

```bash
pip install algovoi-delegation-ref
```

## Use

```python
from algovoi_delegation_ref import delegation_ref, tamper_detected, verify_chain

root = {
    "delegator_id": "did:web:org.example",
    "delegate_id":  "did:web:agent-1.example",
    "scope":        "payments:usdc:<=100",
    "not_before_ms": 1716494400000,
    "not_after_ms":  1716498000000,
    "prev_delegation_ref": "",
}
ref = delegation_ref(root)
tamper_detected(ref, root)                              # False (matches)
tamper_detected(ref, {**root, "scope": "payments:usdc:*"})   # True (scope widened)

# chain a sub-delegation and verify integrity end to end
sub = {**root, "delegator_id": "did:web:agent-1.example",
       "delegate_id": "did:web:agent-2.example",
       "scope": "payments:usdc:<=50", "prev_delegation_ref": ref}
verify_chain([root, sub])    # -> [root_ref, sub_ref]; raises on a broken link
```

Envelope key order does not matter (JCS absorbs it). A non-integer validity bound
(e.g. an RFC-3339 string) is rejected, not hashed.

## Conformance

`conformance/delegation_ref_v1/`: 3 positives (root, reordered-key, chain link),
5 negatives (scope / expiry / delegate / chain-link tamper, plus a rejected
malformed bound), and two invariants (key-order, chain integrity). The verifier
imports only the standard library plus `rfc8785` (no `algovoi` import):

```bash
pip install rfc8785
python conformance/delegation_ref_v1/verify.py
```

## Adopters

Build on `algovoi-delegation-ref`, pin `==0.1.0`, anchor a canonical vector hash,
and keep the `NOTICE`, and you qualify for a free **v0 licence key** for
`algovoi-mandate-auditor`. The gate is `scripts/check_v0_adoption.py`
(dependency + canonical hash anchor + NOTICE + version pin → ISSUE_V0_KEY).
Apply: email [chopmob@gmail.com](mailto:chopmob@gmail.com).

## License

Apache-2.0. Copyright 2026 AlgoVoi. Preserve the `NOTICE` in any distribution.
