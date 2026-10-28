"""Security regressions for agent evidence and guard decisions."""
import pytest

from algovoi_keystone_agent import (
    Denied, Engine, Event, behaviour, keystone_ref, rule, synth_event, synth_ref, trigger,
)


def policy(name, verdict, **kwargs):
    return behaviour(name, on=trigger(), rule=rule(name, lambda ev: verdict), **kwargs)


def test_event_reference_binds_byte_contents_not_only_length():
    first = Event("execution", kwargs={"body": b"safe"})
    second = Event("execution", kwargs={"body": b"evil"})
    assert first.ref != second.ref
    assert first.ref == Event("execution", kwargs={"body": b"safe"}).ref


def test_denied_carries_blocking_record_not_last_allow():
    engine = Engine([policy("deny", "BLOCK"), policy("allow", "ALLOW")],
                    decision_ref=synth_ref(), clock_ms=lambda: 1)
    class Client:
        def write(self):
            pytest.fail("blocked write reached data plane")

    with pytest.raises(Denied) as caught:
        engine.guard(Client()).write()
    assert caught.value.record["verdict"] == "BLOCK"
    assert caught.value.record["behaviour"] == "deny"


def test_on_fire_observer_cannot_rewrite_logged_evidence():
    def observer(record):
        record["verdict"] = "ALLOW"
        record["event_ref"] = "sha256:" + "0" * 64

    engine = Engine([policy("deny", "BLOCK")], decision_ref=synth_ref(),
                    clock_ms=lambda: 1, on_fire=observer)
    engine.dispatch(Event("execution", method="write"))
    logged = engine.log[0]
    body = {k: v for k, v in logged.items() if k != "behaviour_ref"}
    assert logged["verdict"] == "BLOCK"
    assert logged["behaviour_ref"] == keystone_ref(body)


def test_action_cannot_rewrite_recorded_event_reference():
    def action(event, verdict):
        event["kwargs"] = {"target": "attacker"}

    bhv = behaviour("deny", on=trigger(stage="execution"),
                    rule=rule("deny", lambda ev: "BLOCK"), action=action)
    engine = Engine([bhv], decision_ref=synth_ref(), clock_ms=lambda: 1)
    original = Event("execution", method="write", kwargs={"target": "receipts"})
    expected_ref = original.ref
    engine.dispatch(original)
    assert engine.log[0]["event_ref"] == expected_ref


# --- numeric fail-closed ----------------------------------------------------

import pytest as _pytest

from algovoi_keystone_agent.library import flag_over as _flag_over
from algovoi_keystone_agent.library import spend_cap as _spend_cap


@_pytest.mark.parametrize("amount", ["900", True, "abc", None, float("nan"), 900.0001, {}])
def test_spend_cap_fails_closed_on_unusable_amount(amount):
    assert _spend_cap(500).predicate(synth_event("spend_decision", amount=amount)) == "BLOCK"


def test_spend_cap_missing_amount_fails_closed():
    assert _spend_cap(500).predicate(synth_event("spend_decision")) == "BLOCK"


@_pytest.mark.parametrize("amount,expected",
                         [(500, "ALLOW"), ("499.99", "ALLOW"), (500.01, "BLOCK")])
def test_spend_cap_compares_numerically(amount, expected):
    assert _spend_cap(500).predicate(synth_event("spend_decision", amount=amount)) == expected


@_pytest.mark.parametrize("amount", [None, "abc", True, float("nan"), {}])
def test_flag_over_flags_unusable_amount(amount):
    assert _flag_over(100).predicate(synth_event("spend_decision", amount=amount)) == "FLAG"
