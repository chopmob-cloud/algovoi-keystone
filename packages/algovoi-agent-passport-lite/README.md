# algovoi-agent-passport-lite

The **open, lite** origination layer for [AlgoVoi Agent Passport](https://docs.algovoi.co.uk/agent-passport).
It content-addresses the public fields of an agent credential (`agent_id`, `issuer`, `scope`,
`validity_window`) into a deterministic, recomputable `passport_ref`.

This `passport_ref` is exactly the **`agent_ref` that [Spend Guardrail (lite)](https://docs.algovoi.co.uk/spend-guardrail-lite) binds**: pin the passport by hash, then the pre-payment decision is bound to that hash. Change any field and the reference diverges, so a decision made for one agent credential cannot be silently re-attributed to another. Additive over the frozen substrate (Apache-2.0):

```
passport_ref = "sha256:" + SHA-256(JCS({agent_id, issuer, scope, validity_window}))
```

## Lite vs commercial

| | Lite (this package) | [Agent Passport](https://docs.algovoi.co.uk/agent-passport) |
|---|---|---|
| Licence | Apache-2.0, open | Commercial OEM |
| Identity | content-addressed `passport_ref` | **Falcon-1024 PQC credential** |
| Lifecycle | reference only | issue / verify / **revoke**, spend limits |
| Verifier | recompute offline | maintained verifier |

Pin lite, anchor a vector hash, carry the `NOTICE` → free v0 key.

## Install & use

```bash
pip install algovoi-agent-passport-lite
```

```python
from algovoi_agent_passport_lite import passport_ref, verify

ref = passport_ref("agent-001", "did:algo:issuer", "payments", "2026-06-21/2026-09-21")
verify(ref, "agent-001", "did:algo:issuer", "payments", "2026-06-21/2026-09-21")  # True
verify(ref, "agent-002", "did:algo:issuer", "payments", "2026-06-21/2026-09-21")  # False (agent tamper)
```

All four fields are byte-load-bearing; an empty or missing field is rejected, not hashed.

## Conformance

`conformance/agent_passport_lite_v1/`: 3 positives, 4 field-tamper negatives (agent / issuer /
scope / window), 2 rejection negatives (empty field), 2 invariants. `passport_1` and `passport_2`
equal the `agent_1` / `agent_2` references in `spend_guardrail_lite_v1`, so the decision chain
composes. Verifier imports only stdlib + `rfc8785`:

```bash
pip install rfc8785
python conformance/agent_passport_lite_v1/verify.py
```

## Adopters

The 4-check gate is `scripts/check_v0_adoption.py` (dependency + canonical hash anchor + NOTICE +
version pin → ISSUE_V0_KEY). Apply: [chopmob@gmail.com](mailto:chopmob@gmail.com).

## License

Apache-2.0. Copyright 2026 AlgoVoi. Preserve the `NOTICE` in any distribution.
