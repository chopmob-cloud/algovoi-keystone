# algovoi-recompute-drift

Offline **recompute-drift detection** for the AlgoVoi `action_ref`. A holder of a
four-field action record can recompute its identity and detect drift — without
calling the issuer — distinguishing a benign reordering (which RFC 8785 JCS
absorbs) from a real change of a field value, and rejecting a malformed timestamp
form instead of minting it into a clean-looking identity.

Additive over the frozen substrate (Apache-2.0). No new cryptography:

```
action_ref = hex(SHA-256(JCS(RFC 8785)({agent_id, action_type, scope, timestamp_ms})))
```

with an **integer-millisecond** `timestamp_ms` (canon `jcs-rfc8785-v1`).

## Install

```bash
pip install algovoi-recompute-drift
```

## Use

```python
from algovoi_recompute_drift import recompute_action_ref, drift_detected, assert_no_drift

record = {"agent_id": "agent-1", "action_type": "payment",
          "scope": "acme:order-42", "timestamp_ms": 1716494400123}

ref = recompute_action_ref(record)            # canonical recompute
drift_detected(ref, record)                   # False — matches
drift_detected(ref, {**record, "scope": "acme:order-43"})   # True — payload drift
assert_no_drift(ref, record)                  # raises RecomputeDriftError on drift
```

Input key order does not matter — JCS absorbs it. A non-integer `timestamp_ms`
(e.g. an RFC-3339 string) is rejected, not hashed.

## Conformance

`conformance/recompute_drift_v1/` — 3 positives (baseline, reordered-key, unicode),
4 negatives (timestamp / casing / payload drift, and a rejected timestamp form),
and the key-order invariant. The verifier imports only the standard library plus
`rfc8785` (no `algovoi` import) and recomputes each vector:

```bash
pip install rfc8785
python conformance/recompute_drift_v1/verify.py
```

## Adopters

Build on `algovoi-recompute-drift`, pin `==0.1.0`, anchor a canonical vector hash,
and keep the `NOTICE`, and you qualify for a free **v0 licence key** for
`algovoi-mandate-auditor`. The gate is `scripts/check_v0_adoption.py`
(dependency + canonical hash anchor + NOTICE + version pin → ISSUE_V0_KEY).
Apply: email [chopmob@gmail.com](mailto:chopmob@gmail.com).

## License

Apache-2.0. Copyright 2026 AlgoVoi. Preserve the `NOTICE` in any distribution.
