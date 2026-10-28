# algovoi-spend-guardrail-lite

The **open, lite** origination layer for [AlgoVoi Spend Guardrail](https://docs.algovoi.co.uk/spend-guardrail).
One call an agent platform makes **before executing a payment**: bind a categorical
**ALLOW / DENY** decision to the agent it was made for (`agent_ref`), the spend authority
it was checked against (`mandate_ref`), and the policy in force (`policy_bound_ref`),
each imported by hash, into a deterministic, recomputable `guardrail_ref`. **Moves no funds.**

The whole pre-payment decision becomes one content address. Swap the agent, the mandate,
the policy, or the verdict and the `guardrail_ref` diverges: an ALLOW made under one
policy snapshot **does not recompute under a rotated policy**. Additive over the frozen
substrate (Apache-2.0):

```
guardrail_ref = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))
```

## Lite vs commercial

| | Lite (this package) | [Spend Guardrail](https://docs.algovoi.co.uk/spend-guardrail) |
|---|---|---|
| Licence | Apache-2.0, open | Commercial OEM |
| Decision binding | content-addressed `guardrail_ref` | same, **Falcon-1024 signed receipt** |
| Enforcement | bring your own verdict | full **Agent Passport + Payment Mandate** stack |
| Verifier | recompute offline | maintained verifier |

Pin lite, anchor a vector hash, carry the `NOTICE` → free v0 key; upgrade for
post-quantum signing + the enforcement stack.

## Install & use

```bash
pip install algovoi-spend-guardrail-lite
```

```python
from algovoi_spend_guardrail_lite import guardrail_ref, verify

# each input is imported by hash: a passport_ref, a mandate_ref, and a policy_bound_ref
agent  = "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be"
mandate = "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35"
policy = "sha256:aaee2091799f376ee8cac802ea4920feaa4eca52950488a3e047ff82e6959a21"

ref = guardrail_ref("ALLOW", agent, mandate, policy)   # bind the decision
verify(ref, "ALLOW", agent, mandate, policy)           # True
verify(ref, "DENY",  agent, mandate, policy)           # False (verdict tamper)
```

An ALLOW bound under policy P returns a different `guardrail_ref` if recomputed against
the `policy_bound_ref` under a rotated P'; rotation is detectable. Invalid verdicts and
malformed refs are rejected, not hashed.

## Conformance

`conformance/spend_guardrail_lite_v1/`: 2 positives (ALLOW/DENY), 4 divergence negatives
(verdict / policy-rotation / agent / mandate tamper), 2 rejection negatives (invalid
verdict + malformed ref), and 2 invariants. Verifier imports only stdlib + `rfc8785`:

```bash
pip install rfc8785
python conformance/spend_guardrail_lite_v1/verify.py
```

## Adopters

The 4-check gate is `scripts/check_v0_adoption.py` (dependency + canonical hash anchor
+ NOTICE + version pin → ISSUE_V0_KEY). Apply: [chopmob@gmail.com](mailto:chopmob@gmail.com).

## License

Apache-2.0. Copyright 2026 AlgoVoi. Preserve the `NOTICE` in any distribution.
