# algovoi-cloudevents

Emit an AlgoVoi keystone decision as a [CloudEvents](https://cloudevents.io) 1.0 event. The
content-addressed `execution_ref` is the event `id`; the keystone references live in `data` and the
standard `id` / `subject` attributes (no invented context extension attributes, so the event stays
spec-conformant). A consumer recomputes `execution_ref` from `data` with only JCS (RFC 8785) +
SHA-256 and confirms it equals the event `id`.

```python
from algovoi_cloudevents import to_cloudevent, verify_cloudevent_execution_ref
ev = to_cloudevent(decision_ref=dr, action_type="payment", scope="payments/transfer",
                   outcome="COMMITTED", executed_at_ms=1716460800000,
                   source="did:web:api.algovoi.co.uk", stage="execution")
assert verify_cloudevent_execution_ref(ev)   # recompute from data, offline
```

Apache-2.0.
