# algovoi-payment-mandate-lite

The **open, lite** origination layer for AlgoVoi Payment Mandate. It content-addresses the
terms of a spend authority (`payer`, `cap`, `period`, `revocation_state`) into a
deterministic, recomputable `mandate_ref`.

This `mandate_ref` is exactly the **`mandate_ref` that [Spend Guardrail (lite)](https://docs.algovoi.co.uk/spend-guardrail-lite) binds**: pin the mandate by hash, then the pre-payment decision is bound to that hash. Change the cap, the period, or the revocation state and the reference diverges, so a decision made against one authority cannot be silently re-attributed to another. Additive over the frozen substrate (Apache-2.0):

```
mandate_ref = "sha256:" + SHA-256(JCS({cap, payer, period, revocation_state}))
```

## Lite vs commercial

| | Lite (this package) | Payment Mandate (commercial) |
|---|---|---|
| Licence | Apache-2.0, open | Commercial OEM |
| Authority | content-addressed `mandate_ref` | **Falcon-1024 PQC signed mandate** |
| Enforcement | reference only | **authorize-charge** against the per-period cap |
| Verifier | recompute offline | maintained verifier |

Pin lite, anchor a vector hash, carry the `NOTICE` → free v0 key.

## Install & use

```bash
pip install algovoi-payment-mandate-lite
```

```python
from algovoi_payment_mandate_lite import mandate_ref, verify

ref = mandate_ref("0x…payer", "1000", "monthly", "active")   # cap is a string
verify(ref, "0x…payer", "1000", "monthly", "active")          # True
verify(ref, "0x…payer", "2000", "monthly", "active")          # False (cap tamper)
verify(ref, "0x…payer", "1000", "monthly", "revoked")         # False (revocation tamper)
```

All four fields are byte-load-bearing; an empty or missing field is rejected, not hashed.

## Conformance

`conformance/payment_mandate_lite_v1/`: 3 positives, 4 field-tamper negatives (payer / cap /
period / revocation), 2 rejection negatives (empty field), 2 invariants. `mandate_1` and
`mandate_2` equal the `mandate_1` / `mandate_2` references in `spend_guardrail_lite_v1`, so the
decision chain composes. Verifier imports only stdlib + `rfc8785`:

```bash
pip install rfc8785
python conformance/payment_mandate_lite_v1/verify.py
```

## Adopters

The 4-check gate is `scripts/check_v0_adoption.py` (dependency + canonical hash anchor + NOTICE +
version pin → ISSUE_V0_KEY). Apply: [chopmob@gmail.com](mailto:chopmob@gmail.com).

## License

Apache-2.0. Copyright 2026 AlgoVoi. Preserve the `NOTICE` in any distribution.
