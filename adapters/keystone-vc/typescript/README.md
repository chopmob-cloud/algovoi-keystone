# algovoi-keystone-vc

Emit an AlgoVoi keystone decision as a [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/)
(Data Model 2.0). The credential uses our own `KeystoneExecutionCredential` type and `@context`, so
it needs no registration. The content-addressed `executionRef` is the `credentialSubject.id`; a
consumer recomputes it from the subject with only JCS (RFC 8785) + SHA-256, so the credential is
content-bound before any signature suite is applied. Signing (a DataIntegrityProof such as
`eddsa-jcs-2022`) is the issuer's step.

```python
from algovoi_keystone_vc import to_verifiable_credential, verify_vc_execution_ref
vc = to_verifiable_credential(decision_ref=dr, action_type="payment", scope="payments/transfer",
                              outcome="COMMITTED", executed_at_ms=1716460800000,
                              issuer="did:web:api.algovoi.co.uk")
assert verify_vc_execution_ref(vc)   # recompute from credentialSubject, offline
```

Apache-2.0.
