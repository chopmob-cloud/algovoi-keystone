# algovoi-journey-ref

Content-addressed journey references for the AlgoVoi substrate: bind a whole
multi-agent task (its hops, the delegations between them, and a closed outcome)
into one reference that recomputes from its own bytes.

```
journey_ref = "sha256:" + SHA-256(JCS(RFC 8785)({ delegations, hops, journey_outcome }))
```

`hops` and `delegations` are ordered lists of `"sha256:"`-prefixed refs;
`journey_outcome` is one of `COMPLETE`, `PARTIAL`, `ABORTED`. Construction and
tamper-detection only, fully offline: any change to the envelope changes the ref.

## Install

```
pip install algovoi-journey-ref
```

## Use

```python
from algovoi_journey_ref import journey_ref, tamper_detected

ref = journey_ref({
    "hops": ["sha256:" + "a" * 64],
    "delegations": [],
    "journey_outcome": "COMPLETE",
})
assert not tamper_detected(ref, {"hops": ["sha256:" + "a" * 64],
                                 "delegations": [], "journey_outcome": "COMPLETE"})
```

## Wiring into Keystone

A journey binds Keystone decisions by reference. Each hop is a decision or execution
reference your decision layer already computes, and the delegations between agents are
`algovoi-delegation-ref` references. `journey_ref` folds an ordered list of those hop
references, the delegation references, and a closed outcome into one reference, so
verifying a single `journey_ref` proves the whole task and recomputes from its own bytes.

This package is construction and tamper-detection only. The end-to-end proof (identity
and authority continuity, scope never widened, nothing under a revoked grant, no hop
omitted) is a separate AlgoVoi component, the commercial Orchestrator.

Apache-2.0. Byte-identical to the TypeScript twin.
