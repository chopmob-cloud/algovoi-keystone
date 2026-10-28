# algovoi-keystone-adk

Carry an AlgoVoi keystone decision into a Google ADK run. The decision's content-addressed
`execution_ref` is stamped into the ADK session state under `algovoi.keystone.*` (never inside an
ADK reserved field), so anyone reading the run's events recomputes it offline with only JCS
(RFC 8785) and SHA-256 and confirms the action is consistent with the decision that authorized it.

```python
from algovoi_keystone_adk import keystone_before_agent_callback, verify_trace_execution_ref

agent = LlmAgent(
    ...,
    before_agent_callback=keystone_before_agent_callback(
        decision_ref="sha256:2a444c62...", action_type="payment", scope="bilateral",
        outcome="COMMITTED", executed_at_ms=1716460800000,
    ),
)
# after a run, the keystone metadata is in the session state:
verify_trace_execution_ref(session.state)   # True iff execution_ref recomputes
```

`keystone_state_update(...)` returns the dict if you prefer to merge it into a `State` /
`tool_context.state` yourself. The callback only touches `callback_context.state`, so there is no
version coupling. Apache-2.0.
