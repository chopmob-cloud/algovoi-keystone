# algovoi-policy-binding

Additive **policy-snapshot binding** for the AlgoVoi substrate. Binds a
content-addressed policy snapshot over an existing AlgoVoi reference: a
settlement-action `binding_ref` (v1) or a `retention_chain` ref (v0/v1), making a
decision **verifiable against the exact policy version in force** and a policy
**rotation detectable by recomputation**. The canonicalisation base and the
underlying binding/chain are frozen and untouched; this layer only references them
by hash.

```
policy_ref       = "sha256:" + SHA-256(JCS(policy_document))
policy_bound_ref = "sha256:" + SHA-256(JCS({policy_ref, subject_ref}))
```

## Install

```bash
pip install algovoi-policy-binding==0.1.0
```

## Use

```python
from algovoi_policy_binding import policy_ref, policy_bound_ref

policy = {"policy_id": "aml.transfer", "version": 1, "max_amount": 1000, "deny_jurisdictions": ["XX"]}
pref = policy_ref(policy)

# subject_ref is any AlgoVoi reference: a binding_ref, or a retention_chain ref (v0/v1)
binding_ref = "sha256:7dc4a2bf62b3c5eabd10fc875ff7fc10f188666f15838c4a51464cc72e80f6ca"
pbr = policy_bound_ref(binding_ref, pref)
```

Version-agnostic: the same call binds over `retention_chain` v0, v1, or a
`binding_ref`; `subject_ref` is imported purely by hash.

## Conformance

`conformance/policy_binding_v1/` contains the canonical vectors and a standalone
`verify.py` (stdlib + `rfc8785`, no package import). Recompute is the test:

```bash
pip install rfc8785
python conformance/policy_binding_v1/verify.py
```

It checks positives byte-for-byte, the **P→P' rotation** negative on every subject,
key-order invariance, and subject-binding. The subjects are the published canonical
references from
[`chopmob-cloud/algovoi-jcs-conformance-vectors`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors).

## Adoption

This package is itself an adopter of the AlgoVoi substrate, and asks the same of
those who build on it. To qualify for a free v0 licence key for
`algovoi-mandate-auditor`, your project must pass four checks
(`scripts/check_v0_adoption.py`):

1. **Dependency**: `algovoi-policy-binding` declared in your lockfile/manifest.
2. **Vector hash anchor**: at least one canonical `policy_ref` / `policy_bound_ref`
   hash from the conformance set appears in your project (you ran our vectors).
3. **NOTICE**: preserve the `NOTICE` file; it must name AlgoVoi and `algovoi-policy-binding`.
4. **Version pin**: pin `algovoi-policy-binding==0.1.0` (or a wheel `--hash`), not a bare range.

```bash
python scripts/check_v0_adoption.py /path/to/your/project
```

Contact chopmob@gmail.com with your import-by-hash evidence and a copy of the NOTICE.

## License

Apache-2.0. (c) 2026 AlgoVoi. Preserve the `NOTICE` file in any distribution.
