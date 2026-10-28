# algovoi-keystone-autogen

Carry an AlgoVoi keystone decision into an AutoGen conversation. The decision's content-addressed
`execution_ref` rides on a message's `metadata` under `algovoi.keystone.*` (never inside an AutoGen
reserved field), so anyone reading the conversation recomputes it offline with only JCS (RFC 8785)
and SHA-256 and confirms the action is consistent with the decision that authorized it.

```python
from algovoi_keystone_autogen import stamp_message, verify_trace_execution_ref

stamp_message(
    message,
    decision_ref="sha256:2a444c62...", action_type="payment", scope="bilateral",
    outcome="COMMITTED", executed_at_ms=1716460800000,
)
verify_trace_execution_ref(message.metadata)   # True iff execution_ref recomputes
```

`keystone_message_metadata(...)` returns the dict if you prefer to merge it yourself. The package
never imports AutoGen (it stamps any object with a `metadata` dict, or a dict message), so there is
no version coupling. Apache-2.0.
