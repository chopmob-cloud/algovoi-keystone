"""Offline conformance + keystone-connect integration for algovoi-keystone-agent."""
import pytest

from algovoi_keystone_agent import (
    Denied, Engine, behaviour, check_behaviour, check_rule, check_trigger,
    keystone_ref, rule, synth_event, trigger,
)


# --------------------------------------------------------------------------- #
# A worked behaviour: freeze a spend that exceeds a cap.
# --------------------------------------------------------------------------- #

def _freeze_behaviour(cap=500, sink=None):
    cap_rule = rule("spend_cap", lambda ev: "BLOCK" if ev.get("amount", 0) > cap else "ALLOW")
    charge = trigger(stage="spend_decision", where=lambda ev: ev.get("action_type") == "charge")

    def action(ev, verdict):
        if verdict == "BLOCK":
            frozen = {"frozen_ref": keystone_ref({"froze": ev.get("scope"), "amount": ev.get("amount")})}
            if sink is not None:
                sink.append(frozen)
            return frozen
        return None

    return behaviour("freeze_on_cap", on=charge, rule=cap_rule, action=action)


def test_rule_battery():
    cap_rule = rule("spend_cap", lambda ev: "BLOCK" if ev.get("amount", 0) > 500 else "ALLOW")
    report = check_rule(cap_rule, [
        (synth_event("spend_decision", amount=900, action_type="charge"), "BLOCK"),
        (synth_event("spend_decision", amount=100, action_type="charge"), "ALLOW"),
    ])
    assert report.ok, report


def test_trigger_battery():
    charge = trigger(stage="spend_decision", where=lambda ev: ev.get("action_type") == "charge")
    report = check_trigger(
        charge,
        matching=[synth_event("spend_decision", action_type="charge")],
        non_matching=[
            synth_event("spend_decision", action_type="refund"),
            synth_event("execution", action_type="charge"),
        ],
    )
    assert report.ok, report


def test_behaviour_conformance_block():
    bhv = _freeze_behaviour()
    report = check_behaviour(
        bhv,
        [synth_event("spend_decision", amount=900, action_type="charge", scope="acct/1")],
        expect="BLOCK",
    )
    assert report.ok, report


def test_behaviour_allows_under_cap():
    bhv = _freeze_behaviour()
    report = check_behaviour(
        bhv,
        [synth_event("spend_decision", amount=10, action_type="charge", scope="acct/1")],
        expect="ALLOW",
    )
    assert report.ok, report


def test_behaviour_ref_recomputes_byte_for_byte():
    bhv = _freeze_behaviour()
    eng = Engine([bhv], decision_ref="sha256:decision", clock_ms=lambda: 1717000000000)
    fired = eng.dispatch(synth_event("spend_decision", amount=900, action_type="charge", scope="a/1"))
    assert len(fired) == 1
    rec = fired[0]
    body = {k: v for k, v in rec.items() if k != "behaviour_ref"}
    assert keystone_ref(body) == rec["behaviour_ref"]


def test_decision_bound():
    bhv = _freeze_behaviour()
    ev = synth_event("spend_decision", amount=900, action_type="charge", scope="a/1")
    a = Engine([bhv], decision_ref="sha256:AAAA", clock_ms=lambda: 1).dispatch(ev)[0]
    b = Engine([bhv], decision_ref="sha256:BBBB", clock_ms=lambda: 1).dispatch(ev)[0]
    assert a["behaviour_ref"] != b["behaviour_ref"]


def test_action_fires_only_on_block():
    sink = []
    bhv = _freeze_behaviour(sink=sink)
    eng = Engine([bhv], decision_ref="sha256:d", clock_ms=lambda: 1)
    eng.dispatch(synth_event("spend_decision", amount=10, action_type="charge"))
    assert sink == []
    eng.dispatch(synth_event("spend_decision", amount=900, action_type="charge"))
    assert len(sink) == 1


def test_engine_strongest_verdict():
    allow = behaviour("a", on=trigger(stage="x"), rule=rule("allow", lambda ev: "ALLOW"))
    flag = behaviour("f", on=trigger(stage="x"), rule=rule("flag", lambda ev: "FLAG"))
    block = behaviour("b", on=trigger(stage="x"), rule=rule("block", lambda ev: "BLOCK"))
    eng = Engine([allow, flag, block], decision_ref="sha256:d", clock_ms=lambda: 1)
    assert eng.verdict(synth_event("x")) == "BLOCK"


def test_broken_rule_fails_check_never_crashes():
    bad = rule("boom", lambda ev: 1 / 0)
    report = check_rule(bad, [(synth_event("x"), "ALLOW")])
    assert not report.ok  # reported as a failure, not an exception


# --------------------------------------------------------------------------- #
# Integration with keystone-connect: guard a connector, block a real write.
# --------------------------------------------------------------------------- #

def test_guard_blocks_keystone_connect_write():
    connect = pytest.importorskip("algovoi_keystone_connect")

    class FakeS3:
        def __init__(self):
            self.puts = []

        def put_object(self, **kw):
            self.puts.append(kw)
            return {"ETag": "x"}

    keystone_s3 = connect.connector("s3", writes={
        "put_object": ("put", lambda call: "%s/%s" % (call.kwargs["Bucket"], call.kwargs["Key"])),
    })
    decision_ref = keystone_ref({"decision": "let-agent-1-write-receipts"})  # valid sha256:<64hex>
    inner = FakeS3()
    client = keystone_s3(inner, decision_ref=decision_ref)

    # Deny any put to the "locked" bucket.
    deny_locked = behaviour(
        "deny_locked_bucket",
        on=trigger(stage="execution", where=lambda ev: ev.get("method") == "put_object"),
        rule=rule("locked", lambda ev: "BLOCK" if ev["kwargs"].get("Bucket") == "locked" else "ALLOW"),
    )
    eng = Engine([deny_locked], decision_ref=decision_ref, clock_ms=lambda: 1)
    guarded = eng.guard(client)

    # allowed bucket -> write reaches the fake data plane
    guarded.put_object(Bucket="receipts", Key="r1", Body=b"{}")
    assert len(inner.puts) == 1

    # locked bucket -> denied before the write, and the block is recorded
    with pytest.raises(Denied):
        guarded.put_object(Bucket="locked", Key="r2", Body=b"{}")
    assert len(inner.puts) == 1  # no new write
    assert eng.log[-1]["verdict"] == "BLOCK"
    assert eng.log[-1]["behaviour"] == "deny_locked_bucket"
