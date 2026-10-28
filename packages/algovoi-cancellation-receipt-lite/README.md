# algovoi-cancellation-receipt-lite

Open, content-addressed **cancellation references** for the AlgoVoi substrate. The lite, Apache-2.0 origination tier of the commercial AlgoVoi Cancellation Receipt.

```
cancellation_ref = "sha256:" + SHA-256(JCS({ cancellation_reason, mandate_ref }))
```

It content-addresses the cancellation of a spend authority into a deterministic, recomputable reference:

- **`mandate_ref`**: the spend authority being cancelled, imported by hash. This is the same `mandate_ref` [Payment Mandate (lite)](https://pypi.org/project/algovoi-payment-mandate-lite/) produces and [Spend Guardrail (lite)](https://pypi.org/project/algovoi-spend-guardrail-lite/) binds, so the cancellation composes onto the open pre-payment decision chain.
- **`cancellation_reason`**: a closed enum: `USER_REQUESTED`, `MERCHANT_REQUESTED`, `COMPLIANCE_TERMINATED`, `EXPIRED`.

Both fields are byte-load-bearing: change the mandate or the reason and the `cancellation_ref` diverges, so a cancellation cannot be silently re-pointed to another authority and the reason cannot be swapped. A reason outside the enum, or an empty `mandate_ref`, is rejected, not hashed.

## Use

```python
from algovoi_cancellation_receipt_lite import cancellation_ref

ref = cancellation_ref(
    mandate_ref="sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35",
    cancellation_reason="USER_REQUESTED",
)
```

## Lite vs commercial

| | Lite (this package) | Commercial Cancellation Receipt |
|---|---|---|
| Licence | Apache-2.0, open | Commercial OEM |
| Reference | content-addressed `cancellation_ref` | the same, **Falcon-1024 signed receipt** |
| Carries | reason + mandate (by hash) | + effective-from timing, provider, jurisdiction |
| Propagation | bring your own | across settlement + retention chains |
| Verifier | recompute offline | maintained verifier |

## Adopters (pin → key)

If you build on `algovoi-cancellation-receipt-lite`, pin `==0.1.0`, anchor a canonical `cancellation_ref` vector hash from `cancellation_receipt_lite_v1`, and keep the `NOTICE`, you qualify for a free **v0 licence key** for `algovoi-mandate-auditor`. The gate is `scripts/check_v0_adoption.py`. Apply: email chopmob@gmail.com with your import-by-hash evidence and a copy of the NOTICE.

## Conformance

The `cancellation_receipt_lite_v1` vector set is published in the public corpus,
[chopmob-cloud/algovoi-jcs-conformance-vectors](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors),
with Python and Node runners. Python and TypeScript reproduce every value byte-for-byte. `cn-001`, `cn-002` and `cn-003` cancel `mandate_1`, the `mandate_ref` in `spend_guardrail_lite_v1`.

Apache-2.0. Additive over the frozen canonicalisation substrate; sole AlgoVoi authorship.
