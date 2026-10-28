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
from algovoi_keystone_agent import check_behaviour, synth_event
from algovoi_keystone_agent.library import cap_charges, deny_writes_to

rt = Runtime(Journal("keystone.db"), decision_ref=decision_ref)

passport_ref = rt.record_stage("passport", {"agent": "agent-7", "issuer": "acme"})
rt.record_stage("mandate", {"passport_ref": passport_ref, "cap": "500USD"})

# The spend cap is a DECISION-stage behaviour: evaluate it against the decision
# before you write, not inside the write guard.
check = check_behaviour(cap_charges(500), [synth_event("spend_decision", amount=900)])
assert not check.ok      # 900 > 500: the decision is BLOCK, so do not proceed

# The write guard enforces EXECUTION-stage behaviours. Its triggers must match the
# stage it dispatches, or the gate would never fire; bind() refuses those loudly.
s3 = rt.bind(keystone_s3_client, behaviours=[deny_writes_to("Bucket", ["locked"])])
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

## Verify against a trusted anchor, and inspect read-only

A chain check alone cannot see the newest rows being dropped -- what remains is a valid prefix. Pin
the head (and optionally the count) somewhere else and pass it back:

```python
rep = journal.verify(expected_head=last_known_head, expected_count=last_known_count)
assert rep.ok

with Journal("keystone.db", read_only=True) as ro:      # never creates or writes the file
    assert ro.verify(expected_head=last_known_head).ok
```

`expect_head` / `expect_count` are accepted as aliases. A malformed pin raises `ValueError`; an
unreadable or non-journal database returns a failed report instead of raising.

## What counts as a valid record

`append()` refuses anything `verify_record()` cannot recompute, so a journal can never hold a record
that fails its own check. Each record carries exactly one self-reference:

- `stage_ref` / `behaviour_ref` -- hashed over every other field, so any edit (including
  `decision_ref`) breaks it;
- `execution_ref` -- hashed over the five execution-tier fields only, so unrelated extra fields on
  the record are *not* authenticated;
- an `execution_keystone` wrapper from `algovoi_execution_ref.bind_keystone` -- `decision_ref`,
  `execution_ref`, `trust_query_ref` and `chain` are all recomputed by that package; a record
  carrying trust fields without forming a valid wrapper is rejected.

Runtimes also refuse a stage payload that claims a different `decision_ref`, and refuse to bind a
connect client built for another decision.

This is the open journal. The commercial audit-chain is the same shape with durable, post-quantum
signed, append-only storage. Built on the AlgoVoi substrate (RFC 8785 JCS + SHA-256).
