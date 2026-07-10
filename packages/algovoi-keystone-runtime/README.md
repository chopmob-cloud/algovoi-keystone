# algovoi-keystone-runtime

Run a Keystone chain and keep the evidence. The runtime assembles stages, connectors and behaviours
into one running pipeline: it gates writes through the behaviour layer and journals every emitted
reference, the governance decision (`behaviour_ref`) and the write it authorised (`execution_ref`),
plus any stage refs you record. The journal is a queryable, tamper-evident SQLite store, and every
entry recomputes offline from its own fields with stock RFC 8785 + SHA-256. No AlgoVoi software in
your trust base. Apache-2.0.

## Run a chain, keep the record

```python
from algovoi_keystone_runtime import Journal, Runtime
from algovoi_keystone_agent.library import cap_charges, deny_writes_to

rt = Runtime(Journal("keystone.db"), decision_ref=decision_ref)

passport_ref = rt.record_stage("passport", {"agent": "agent-7", "issuer": "acme"})
rt.record_stage("mandate", {"passport_ref": passport_ref, "cap": "500USD"})

s3 = rt.bind(keystone_s3_client, behaviours=[cap_charges(500), deny_writes_to("Bucket", ["locked"])])
s3.put_object(Bucket="receipts", Key="r1.json", Body=b"{}")   # gated + journaled
s3.put_object(Bucket="locked",   Key="x.json",  Body=b"{}")   # denied before commit, block recorded
```

`bind` returns a client that gates each write through the behaviours and records both the
`behaviour_ref` (every firing) and the `execution_ref` (every committed write). Reads pass through and
journal nothing. `record_stage` journals the upstream stages of the chain.

## Query, verify, replay

```python
rt.journal.chain(decision_ref)     # every record under a decision, in order
rt.journal.by_kind("execution")    # filter by execution / behaviour / stage
rt.journal.head()                  # the tamper-evident chain tip

report = rt.journal.verify()       # every record recomputes AND the hash chain is intact
assert report.ok
```

`verify()` proves two things at once: each stored reference recomputes from its own fields, and the
journal is a hash chain over those references, so nothing has been inserted, removed or reordered.
`export()` dumps every record for external offline verification by any third party.

This is the open journal. The commercial audit-chain is the same shape with durable, post-quantum
signed, append-only storage. Built on the AlgoVoi substrate (RFC 8785 JCS + SHA-256).
