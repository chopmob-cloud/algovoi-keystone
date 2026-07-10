"""Conformance for the starter behaviour library."""
import pytest

from algovoi_keystone_agent import (
    Denied, Engine, check_behaviour, check_rule, keystone_ref, synth_event,
)
from algovoi_keystone_agent.library import (
    allow_list, cap_charges, deny_list, deny_writes_to, flag_over,
    flag_large_charges, require_fields, restrict_scope, scope_fence, spend_cap,
)


def test_spend_cap_rule():
    r = check_rule(spend_cap(500), [
        (synth_event("spend_decision", amount=900), "BLOCK"),
        (synth_event("spend_decision", amount=500), "ALLOW"),
        (synth_event("spend_decision"), "ALLOW"),  # missing amount -> 0
    ])
    assert r.ok, r


def test_flag_over_rule():
    r = check_rule(flag_over(100), [
        (synth_event("spend_decision", amount=200), "FLAG"),
        (synth_event("spend_decision", amount=50), "ALLOW"),
    ])
    assert r.ok, r


def test_deny_and_allow_list():
    r1 = check_rule(deny_list("chain", ["tron"]), [
        (synth_event("execution", chain="tron"), "BLOCK"),
        (synth_event("execution", chain="base"), "ALLOW"),
    ])
    r2 = check_rule(allow_list("chain", ["base", "solana"]), [
        (synth_event("execution", chain="base"), "ALLOW"),
        (synth_event("execution", chain="tron"), "BLOCK"),
    ])
    assert r1.ok and r2.ok, (r1, r2)


def test_scope_fence_prefix():
    r = check_rule(scope_fence(["acct/7/", "acct/8/"]), [
        (synth_event("execution", scope="acct/7/receipts"), "ALLOW"),
        (synth_event("execution", scope="acct/9/secrets"), "BLOCK"),
    ])
    assert r.ok, r


def test_require_fields():
    r = check_rule(require_fields("decision_ref", "scope"), [
        (synth_event("execution", scope="a/1"), "ALLOW"),   # synth adds decision_ref
        (synth_event("execution"), "BLOCK"),                # no scope
    ])
    assert r.ok, r


def test_reads_nested_kwargs():
    # a guarded-connector event carries params under kwargs
    ev = synth_event("execution", method="put_object", kwargs={"Bucket": "locked", "Key": "r"})
    r = check_rule(deny_list("Bucket", ["locked"]), [(ev, "BLOCK")])
    assert r.ok, r


def test_cap_charges_behaviour():
    r = check_behaviour(
        cap_charges(500),
        [synth_event("spend_decision", amount=900, action_type="charge", scope="a/1")],
        expect="BLOCK",
    )
    assert r.ok, r


def test_flag_large_charges_behaviour():
    r = check_behaviour(
        flag_large_charges(100),
        [synth_event("spend_decision", amount=900, action_type="charge", scope="a/1")],
        expect="FLAG",
    )
    assert r.ok, r


def test_deny_writes_to_guards_connect_client():
    connect = pytest.importorskip("algovoi_keystone_connect")

    class FakeDynamo:
        def __init__(self):
            self.puts = []

        def put_item(self, **kw):
            self.puts.append(kw)
            return {}

    ks_dynamo = connect.connector("dynamodb", writes={
        "put_item": ("put", lambda call: call.kwargs["TableName"]),
    })
    dref = keystone_ref({"grant": "agent-7"})
    inner = FakeDynamo()
    client = ks_dynamo(inner, decision_ref=dref)

    eng = Engine(
        [deny_writes_to("TableName", ["ledger_locked"], method="put_item")],
        decision_ref=dref, clock_ms=lambda: 1,
    )
    guarded = eng.guard(client)

    guarded.put_item(TableName="events", Item={"id": "1"})     # allowed
    assert len(inner.puts) == 1
    with pytest.raises(Denied):
        guarded.put_item(TableName="ledger_locked", Item={"id": "2"})
    assert len(inner.puts) == 1
    assert eng.log[-1]["verdict"] == "BLOCK"


def test_restrict_scope_behaviour():
    r = check_behaviour(
        restrict_scope(["acct/7/"], method="put_object"),
        [synth_event("execution", method="put_object", scope="acct/9/x")],
        expect="BLOCK",
    )
    assert r.ok, r
