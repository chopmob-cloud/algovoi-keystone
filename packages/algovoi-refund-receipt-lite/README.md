# algovoi-refund-receipt-lite

Open, content-addressed **refund references** for the AlgoVoi substrate. The lite, Apache-2.0 origination tier of the commercial AlgoVoi Refund Receipt.

```
refund_ref = "sha256:" + SHA-256(JCS({ refund_amount, refund_result, subject_ref }))
```

It content-addresses the refund of a prior payment into a deterministic, recomputable reference:

- **`subject_ref`**: the payment/decision being refunded, imported by hash. Typically the `guardrail_ref` of the [pre-payment decision](https://pypi.org/project/algovoi-spend-guardrail-lite/) or a settlement reference, so the refund composes onto the decision chain and closes the lifecycle after settlement.
- **`refund_result`**: a closed enum: `FULL`, `PARTIAL`, `REJECTED`.
- **`refund_amount`**: the amount returned, as a string (`"0"` for a REJECTED refund).

All three fields are byte-load-bearing: change the subject, the result, or the amount and the `refund_ref` diverges, so a refund cannot be silently re-pointed to another payment and neither the outcome nor the amount can be changed. A result outside the enum, or an empty `subject_ref`/`refund_amount`, is rejected, not hashed.

## Use

```python
from algovoi_refund_receipt_lite import refund_ref

ref = refund_ref(
    subject_ref="sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97",
    refund_result="FULL",
    refund_amount="1000",
)
```

## Lite vs commercial

| | Lite (this package) | Commercial Refund Receipt |
|---|---|---|
| Licence | Apache-2.0, open | Commercial OEM |
| Reference | content-addressed `refund_ref` | the same, **Falcon-1024 signed receipt** |
| Carries | result + amount + subject (by hash) | + provider, timing, jurisdiction |
| Propagation | bring your own | closes original payment across settlement + retention chains |
| Verifier | recompute offline | maintained verifier |

## Adopters (pin → key)

If you build on `algovoi-refund-receipt-lite`, pin `==0.1.0`, anchor a canonical `refund_ref` vector hash from `refund_receipt_lite_v1`, and keep the `NOTICE`, you qualify for a free **v0 licence key** for `algovoi-mandate-auditor`. The gate is `scripts/check_v0_adoption.py`. Apply: email chopmob@gmail.com with your import-by-hash evidence and a copy of the NOTICE.

## Conformance

The `refund_receipt_lite_v1` vector set is published in the public corpus,
[chopmob-cloud/algovoi-jcs-conformance-vectors](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors),
with Python and Node runners. Python and TypeScript reproduce every value byte-for-byte. `rf-001`, `rf-002` and `rf-003` refund the ALLOW `guardrail_ref` in `spend_guardrail_lite_v1` / `spend_decision_chain_v1`.

Apache-2.0. Additive over the frozen canonicalisation substrate; sole AlgoVoi authorship.
