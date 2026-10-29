"""The event handed to a behaviour must not be able to change what later behaviours see.

A single mutable Event was passed to every behaviour in a dispatch, so an earlier
behaviour's action could rewrite the fields a later rule inspects. That turns a
guard into theatre: the deny rule evaluates a value the data plane never writes.
"""
import copy

import pytest

from algovoi_keystone_agent import Denied, Engine, Event, behaviour, rule, trigger
from algovoi_keystone_agent.library import deny_writes_to


class Client:
    def __init__(self):
        self.calls = []

    def write(self, **kw):
        self.calls.append(dict(kw))
        return "written"

    def delete_object(self, **kw):
        self.calls.append(dict(kw))
        return "deleted"


def _mask(**fields):
    def action(event, verdict):
        event["kwargs"].update(fields)
        return {"masked": dict(fields)}
    return action


def test_action_cannot_hide_the_value_a_later_rule_denies():
    """Caller writes the denied value; an earlier behaviour renames it to a safe one."""
    masking = behaviour("mask", on=trigger(stage="execution"),
                        rule=rule("always", lambda e: "ALLOW"), action=_mask(Bucket="public"))
    client = Client()
    engine = Engine([masking, deny_writes_to("Bucket", ["locked"])], decision_ref="d1")
    with pytest.raises(Denied):
        engine.guard(client).write(Bucket="locked")
    assert client.calls == [], "denied write must never reach the data plane"


def test_baseline_still_blocks_without_the_masking_behaviour():
    client = Client()
    engine = Engine([deny_writes_to("Bucket", ["locked"])], decision_ref="d2")
    with pytest.raises(Denied):
        engine.guard(client).write(Bucket="locked")
    assert client.calls == []


def test_action_cannot_change_stage_to_suppress_a_later_block():
    def stage_mutator(event, verdict):
        event.stage = "not_execution"
        return {"stage": event.stage}

    mutator = behaviour("mutator", on=trigger(stage="execution"),
                        rule=rule("always", lambda e: "ALLOW"), action=stage_mutator)
    client = Client()
    engine = Engine([mutator, deny_writes_to("Bucket", ["locked"])], decision_ref="d3")
    with pytest.raises(Denied):
        engine.guard(client).delete_object(Bucket="locked")
    assert client.calls == []


def test_rule_verdict_is_computed_on_the_caller_s_value():
    seen = []

    def peek(event, verdict):
        seen.append(event["kwargs"].get("Bucket"))
        event["kwargs"]["Bucket"] = "public"
        return None

    watcher = behaviour("watcher", on=trigger(stage="execution"),
                        rule=rule("always", lambda e: "ALLOW"), action=peek)
    deny = deny_writes_to("Bucket", ["locked"])
    engine = Engine([watcher, deny], decision_ref="d4")
    fired = engine.dispatch(Event("execution", {"method": "write", "kwargs": {"Bucket": "locked"}}))
    verds = {r["behaviour"]: r["verdict"] for r in fired}
    assert verds[deny.name] == "BLOCK", verds
    assert seen == ["locked"]


def test_observer_cannot_corrupt_the_journal_through_a_nested_copy():
    tampered = []

    def observer(record):
        # dict(record) is shallow: mutating a nested value rewrote the stored record
        if isinstance(record.get("action_outcome"), dict):
            record["action_outcome"]["nested"] = "tampered"
            tampered.append(record["behaviour"])

    def action(event, verdict):
        return {"nested": "original"}

    b = behaviour("nested", on=trigger(stage="execution"),
                  rule=rule("always", lambda e: "ALLOW"), action=action)
    engine = Engine([b], decision_ref="d5", on_fire=observer)
    engine.dispatch(Event("execution", {"method": "write", "kwargs": {}}))
    assert tampered, "observer did not run"
    stored = engine.log[0]["action_outcome"]
    assert stored["nested"] == "original", stored


def test_mutation_does_not_leak_into_the_next_dispatch():
    def poison(event, verdict):
        event["kwargs"]["Bucket"] = "public"
        return None

    poisoner = behaviour("poison", on=trigger(stage="execution"),
                         rule=rule("always", lambda e: "ALLOW"), action=poison)
    deny = deny_writes_to("Bucket", ["locked"])
    engine = Engine([poisoner, deny], decision_ref="d6")
    ev = Event("execution", {"method": "write", "kwargs": {"Bucket": "locked"}})
    first = engine.dispatch(ev)
    assert {r["behaviour"]: r["verdict"] for r in first}[deny.name] == "BLOCK"
    # the caller's own event object must be untouched by behaviours
    assert ev["kwargs"]["Bucket"] == "locked"
