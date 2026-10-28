# algovoi-execution-ref

Decision-bound execution evidence, bound to the keystone. A standalone, pinned,
Apache-2.0 app.

`execution_ref` proves an executed action is consistent with the decision that
authorized it, not merely correlated with an identity:

```
execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope, outcome, executed_at_ms}))
```

It binds the full keystone chain:

```
passport_ref -> mandate_ref -> policy_bound_ref -> decision_ref -> execution_ref -> trust_query_ref
 (identity)     (authority)     (policy)            (decision)      (execution)      (one verdict)
```

## Runs on any substrate version (v0 and v1)

This app uses only the substrate's JCS canonicalisation, which is byte-stable and
present in every release. It pins `algovoi-substrate>=0.3.0` and runs unchanged on
substrate v0 (0.x) and v1 (1.x). You get `execution_ref` and the keystone **without
upgrading your substrate**:

```
pip install algovoi-execution-ref     # installs next to whatever substrate you already have
```

## Use

```python
from algovoi_execution_ref import bind_keystone, verify_record, execution_ref

record = bind_keystone(
    passport_ref="sha256:...", mandate_ref="sha256:...", policy_bound_ref="sha256:...",
    verdict="ALLOW", action_type="payment", scope="bilateral",
    outcome="COMMITTED", executed_at_ms=1716460800000, trust_outcome="TRUSTED",
)
record["execution_ref"]    # decision-bound execution evidence
record["trust_query_ref"]  # content address: one verdict over the whole chain
verify_record(record)      # recomputes every ref from raw fields -> True
```

## CLI

```
echo '{"passport_ref":"sha256:...", ...}' | algovoi-execution-ref
algovoi-execution-ref --verify < record.json    # exit 0 if consistent, 1 if not
```

## Conformance and tiers

The composed chain reproduces the public corpus byte for byte
(`execution_ref_v1` and the `keystone_v1` composition). This is the open tier: it
binds and proves. Post-quantum signing and CCC-ingestable evidence chains are the
commercial Substrate 2 tier. `outcome` is the closed enum
`{COMMITTED, SKIPPED, FAILED, REVERSED}`; `executed_at_ms` is an integer
epoch-millisecond; no raw agent id appears in the preimage, so it carries no PII.
