# algovoi-compliance-gate-lite

The **open, lite** origination layer for [AlgoVoi Compliance Gate](https://docs.algovoi.co.uk/compliance-gate-v2).
You bring a categorical screening verdict (**ALLOW / REFER / DENY**) from your own
sanctions / PEP / AML provider; this binds it to a **no-PII** payer reference and to a
**pinned subject ref** (a `policy_bound_ref`, settlement-action `binding_ref`, or
`retention_chain_ref`) into a deterministic, recomputable `gate_ref`.

Because the verdict is bound to the subject by hash, a decision made under one policy
snapshot **does not recompute under a rotated policy**; the verdict is provably tied
to the policy that was in force. Additive over the frozen substrate (Apache-2.0):

```
payer_ref = "sha256:" + SHA-256(JCS({address, network}))      # address in, only the hash out
gate_ref  = "sha256:" + SHA-256(JCS({payer_ref, subject_ref, verdict}))
```

## Lite vs commercial

| | Lite (this package) | [Compliance Gate v2](https://docs.algovoi.co.uk/compliance-gate-v2) |
|---|---|---|
| Licence | Apache-2.0, open | Commercial OEM |
| Verdict binding | content-addressed `gate_ref` | same, **Falcon-1024 signed** |
| Privacy proof | (none) | **Proofs** (zero-knowledge) |
| Verifier | recompute offline | maintained verifier |

Pin lite, anchor a vector hash, carry the `NOTICE` → free v0 key; upgrade to v2 for
post-quantum signing + Proofs.

## Install & use

```bash
pip install algovoi-compliance-gate-lite
```

```python
from algovoi_compliance_gate_lite import payer_ref, gate_ref, verify

payer = payer_ref("base", "0x…payer")                 # no PII: only sha256 comes out
# subject is any pinned ref, e.g. a policy_bound_ref from algovoi-policy-binding
ref = gate_ref("ALLOW", payer, "sha256:aaee2091…")     # bind verdict to payer + policy
verify(ref, "ALLOW", payer, "sha256:aaee2091…")        # True
verify(ref, "DENY",  payer, "sha256:aaee2091…")        # False (verdict tamper)
```

A verdict bound under policy P returns a different `gate_ref` if recomputed against the
policy_bound_ref under a rotated P'; rotation is detectable. Invalid verdicts and
malformed refs are rejected, not hashed.

## Conformance

`conformance/compliance_gate_lite_v1/`: payer_ref + 3 positives (ALLOW/REFER/DENY),
5 negatives (verdict / policy-rotation / payer tamper; invalid verdict + malformed ref
rejected), and 2 invariants. Verifier imports only stdlib + `rfc8785`:

```bash
pip install rfc8785
python conformance/compliance_gate_lite_v1/verify.py
```

## Adopters

The 4-check gate is `scripts/check_v0_adoption.py` (dependency + canonical hash anchor
+ NOTICE + version pin → ISSUE_V0_KEY). Apply: [chopmob@gmail.com](mailto:chopmob@gmail.com).

## License

Apache-2.0. Copyright 2026 AlgoVoi. Preserve the `NOTICE` in any distribution.
