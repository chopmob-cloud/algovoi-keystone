# algovoi-keystone-langchain

Carry an AlgoVoi keystone decision into a LangChain run trace. The decision's content-addressed
`execution_ref` rides along as run metadata and a tag, under the vendor namespace
`algovoi.keystone.*` (never inside a LangChain reserved field). Anyone reading the trace recomputes
`execution_ref` from the run metadata alone with only JCS (RFC 8785) and SHA-256, and confirms the
agent's recorded action is consistent with the decision that authorized it. The reference is bound
to the decision, not merely correlated with a run.

```python
from algovoi_keystone_langchain import keystone_config, verify_trace_execution_ref

# attach the keystone reference to a LangChain run
result = chain.invoke(
    user_input,
    config=keystone_config(
        decision_ref="sha256:2a444c62...",   # the pre-payment decision (from the keystone)
        action_type="payment", scope="bilateral",
        outcome="COMMITTED", executed_at_ms=1716460800000,
    ),
)
```

The run's metadata now carries `algovoi.keystone.execution_ref` and the keystone preimage fields, so
LangSmith (or any tracer) shows a recomputable reference. Verify it offline from the metadata:

```python
verify_trace_execution_ref(run.metadata)   # True iff execution_ref recomputes
```

`keystone_trace_metadata(...)` returns the framework-neutral attribute dict if you want to attach it
yourself; `make_callback_handler(...)` builds a LangChain callback handler (needs the `langchain`
extra) carrying the same metadata. Python and TypeScript (`@algovoi/keystone-langchain`) produce the
same `execution_ref` byte for byte. Apache-2.0.
