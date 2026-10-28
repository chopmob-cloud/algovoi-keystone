# algovoi-keystone-crewai

Carry an AlgoVoi keystone decision into a crewAI run. The decision's content-addressed
`execution_ref` is recorded into the crew's run under `algovoi.keystone.*` (never inside a crewAI
reserved field), so anyone reading the run recomputes it offline with only JCS (RFC 8785) and
SHA-256 and confirms the action is consistent with the decision that authorized it.

```python
from algovoi_keystone_crewai import keystone_step_callback, verify_trace_execution_ref

sink = []
crew = Crew(
    agents=[...], tasks=[...],
    step_callback=keystone_step_callback(
        decision_ref="sha256:2a444c62...", action_type="payment", scope="bilateral",
        outcome="COMMITTED", executed_at_ms=1716460800000, sink=sink,
    ),
)
crew.kickoff()
verify_trace_execution_ref(sink[0])   # True iff execution_ref recomputes
```

`keystone_trace_metadata(...)` returns the framework-neutral attribute dict. The package never
imports crewAI (the callback is a plain callable), so there is no version coupling. Apache-2.0.
