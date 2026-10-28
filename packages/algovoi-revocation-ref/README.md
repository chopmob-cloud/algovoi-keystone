# algovoi-revocation-ref

Content-addressed revocation references for the AlgoVoi substrate: revoke a
delegation (or other authority) before it expires, tamper-evidently. The
`revocation_ref` is the content hash of the revocation envelope, so any change to
the target, time, reason or revoker changes the ref and is detectable offline.
Revocations chain via `prev_revocation_ref`.

```
revocation_ref = "sha256:" + SHA-256(JCS(RFC 8785)({
    prev_revocation_ref, reason, revoked_at_ms, revoked_ref, revoker_id }))
```

`revoked_at_ms` is an integer-millisecond timestamp; `reason` is one of
`COMPROMISE`, `SUPERSEDED`, `POLICY`, `EXPIRY`, `MANUAL`. Construction,
tamper-detection and chain verification only, fully offline.

## Install

```
pip install algovoi-revocation-ref
```

## Use

```python
from algovoi_revocation_ref import revocation_ref, verify_chain

ref = revocation_ref({
    "revoker_id": "did:web:example.com",
    "revoked_ref": "sha256:" + "a" * 64,
    "reason": "COMPROMISE",
    "revoked_at_ms": 1737000000000,
    "prev_revocation_ref": "",
})
```

## Wiring into Keystone

A revocation binds a Keystone grant by reference. `revoked_ref` is the content-addressed
reference of the delegation (or other authority) being pulled back, and revocations chain
through `prev_revocation_ref` into a tamper-evident sequence you check with `verify_chain`.
A decision or journey compares its references against the revocation chain so nothing acts
under a revoked grant.

This package is construction, tamper-detection and chain verification only. The revocation
cascade proof (that an action at or after `revoked_at_ms` acted under revoked authority,
even across several hops) is a separate AlgoVoi component, the commercial Orchestrator.

Apache-2.0. Byte-identical to the TypeScript twin.
