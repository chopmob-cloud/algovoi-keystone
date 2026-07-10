# algovoi-keystone-agent

The agentic behaviour layer for Keystone: make an agent govern itself. Declare **rules**,
**triggers** and **behaviours** as small specs, deploy them in an `Engine`, and gate any
`keystone-connect` write. Every firing produces a content-addressed `behaviour_ref`, so the agent's
own governance decisions are verifiable Keystone records, recomputable offline with a stock RFC 8785
implementation and standard SHA-256. No AlgoVoi software in your trust base. Apache-2.0.

Pairs with [algovoi-keystone-connect](https://pypi.org/project/algovoi-keystone-connect/): connectors
bind writes to the decision that authorised them; behaviours decide, gate and react to those writes.

## Define a behaviour in a few lines

```python
from algovoi_keystone_agent import rule, trigger, behaviour, Engine

cap    = rule("spend_cap", lambda ev: "BLOCK" if ev.get("amount", 0) > 500 else "ALLOW")
charge = trigger(stage="spend_decision", where=lambda ev: ev.get("action_type") == "charge")
freeze = behaviour("freeze_on_cap", on=charge, rule=cap,
                   action=lambda ev, verdict: {"froze": ev.get("scope")} if verdict == "BLOCK" else None)

engine = Engine([freeze], decision_ref=decision_ref)
for record in engine.dispatch(spend_event):
    ...  # record["behaviour_ref"] recomputes byte for byte
```

- **rule** -- a pure predicate to a verdict (`"ALLOW"` / `"FLAG"` / `"BLOCK"`, or a bool).
- **trigger** -- `stage` plus a `where(event)` predicate: when does this behaviour wake.
- **behaviour** -- `trigger` + `rule` + optional `action(event, verdict)`.
- **Engine** -- deploys behaviours; `dispatch(event)` fires matches and emits a `behaviour_ref`
  record; `verdict(event)` returns the strongest verdict (BLOCK > FLAG > ALLOW).

## Gate a real write

`Engine.guard(client)` wraps a keystone-connect client so each call is dispatched as an event first.
A `BLOCK` denies the call before it reaches the data plane; reads and non-matching calls pass through.

```python
from algovoi_keystone_agent import Denied

guarded = engine.guard(keystone_s3_client)
guarded.put_object(Bucket="receipts", Key="r1", Body=b"{}")   # allowed
guarded.put_object(Bucket="locked",   Key="r2", Body=b"{}")   # raises Denied, no write, block recorded
```

## Test a behaviour at any stage of the flow

You do not need a live gateway or real payments. `synth_event(stage)` stands in for whatever precedes
your behaviour, and the `check_*` battery verifies the keystone properties offline.

```python
from algovoi_keystone_agent import check_rule, check_trigger, check_behaviour, synth_event

report = check_behaviour(
    freeze,
    [synth_event("spend_decision", amount=900, action_type="charge", scope="acct/7")],
    expect="BLOCK",
)
assert report.ok   # fires, behaviour_ref recomputes, self-describing, decision-bound, tamper-evident
print(report)
```

A behaviour that ignores its `decision_ref`, or a rule that is not deterministic, fails `report.ok`.
The battery reports a broken behaviour; it never crashes on one.

Keystone-only edition, Apache-2.0. Built on the AlgoVoi substrate (RFC 8785 JCS + SHA-256).
