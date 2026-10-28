# algovoi-otel-genai

Map an AlgoVoi keystone decision to OpenTelemetry `gen_ai.agent.*` attributes
(open-telemetry/semantic-conventions-genai), and attach `algovoi.keystone.execution_ref` as an
open, recomputable cross-producer key.

The standard `gen_ai.agent.*` trust/drift/scan attributes are producer-emitted and opaque. This
adapter emits them from a keystone decision and adds `execution_ref` =
`"sha256:" + SHA-256(JCS({decision_ref, action_type, scope, outcome, executed_at_ms}))`, which any
consumer recomputes from the span alone with only JCS (RFC 8785) + SHA-256. It binds the action to
the authorizing `decision_ref` (consistency, not just correlation).

```python
from algovoi_otel_genai import to_gen_ai_attributes, verify_gen_ai_execution_ref
attrs = to_gen_ai_attributes(decision_ref=dr, action_type="payment", scope="payments/transfer",
                             outcome="COMMITTED", executed_at_ms=1716460800000,
                             public_key_algorithm="ml-dsa-65",
                             trust={"score": 0.92, "method": "atb-v2"})
assert verify_gen_ai_execution_ref(attrs)   # recomputes execution_ref from the span, offline
```

Apache-2.0.
