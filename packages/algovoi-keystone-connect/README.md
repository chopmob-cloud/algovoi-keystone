# algovoi-keystone-connect

Build and test Keystone bolt-ons with almost no boilerplate. Two halves: **build** a data-plane
connector from a declarative spec, and **test** any bolt-on at any stage of the flow offline. Every
reference is `"sha256:" + SHA-256(RFC 8785 JCS(payload))` — no magic, no AlgoVoi software in the
trust base. Apache-2.0.

## Build a connector in ~12 lines

```python
from algovoi_keystone_connect import connector

keystone_s3 = connector("s3", writes={
    "put_object":    ("put",    lambda call: f"{call.kwargs['Bucket']}/{call.kwargs['Key']}"),
    "delete_object": ("delete", lambda call: f"{call.kwargs['Bucket']}/{call.kwargs['Key']}"),
})

client = keystone_s3(boto3_s3, decision_ref=decision_ref)
client.put_object(Bucket="receipts", Key="2026/r1.json", Body=b"{}")   # bound
ref = client.execution_ref
```

`writes` maps each write method to `(action, scope_fn)`; `scope_fn(call)` reads `call.kwargs` /
`call.args` for per-call values and `call.client` for fixed context (a container name, a queue
entity). Reads pass through unbound. Records on `client.executions` drop straight into
`algovoi-keystone-validate`, and the emitted `execution_ref` is **byte-identical** to a hand-written
connector.

## Test a bolt-on at any stage of the flow

You do not need a live gateway. `synth_ref(stage)` gives a content-addressed stand-in for whatever
precedes your bolt-on, and the `check_*` battery verifies the keystone properties.

```python
from algovoi_keystone_connect import check_connector, check_ref_builder, synth_ref

# execution stage: a connector
report = check_connector(keystone_s3, FakeS3(), [
    ("put_object", {"Bucket": "receipts", "Key": "r1"}),
])
assert report.ok   # recompute, decision-bound, tamper-evident, self-describing

# any stage: a ref-builder that aliases onto the chain (passport / mandate / policy / ...)
def mandate_ref(payload):
    return __import__("algovoi_keystone_connect").keystone_ref(payload)

report = check_ref_builder(
    mandate_ref,
    {"passport_ref": synth_ref("passport"), "limit": "100USD", "scope": "payments"},
    prev_field="passport_ref",   # checks it binds to its predecessor
)
assert report.ok   # deterministic, content-addressed, tamper-evident, predecessor-bound
print(report)
```

The battery catches broken bolt-ons: a connector that ignores `decision_ref`, or a ref-builder that
is not content-addressed, fails `report.ok`.

Keystone-only edition, Apache-2.0. Built on the AlgoVoi substrate (RFC 8785 JCS + SHA-256).
