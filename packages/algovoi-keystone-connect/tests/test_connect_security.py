"""Regression tests for connector evidence and execution boundaries."""
import asyncio

import pytest

from algovoi_execution_ref import execution_ref
from algovoi_keystone_connect import connector, synth_ref


class Client:
    def __init__(self):
        self.calls = []

    def write(self, **kwargs):
        self.calls.append(kwargs)
        return "written"


@pytest.mark.parametrize("decision,scope,ts", [
    ("invalid", "scope", 1),
    (synth_ref(), "", 1),
    (synth_ref(), "scope", -1),
    (synth_ref(), "scope", True),
    (synth_ref(), "scope", 1.5),
])
def test_invalid_evidence_never_reaches_data_plane(decision, scope, ts):
    inner = Client()
    factory = connector("test", writes={"write": ("write", lambda call: scope)})
    with pytest.raises((ValueError, TypeError)):
        bound = factory(inner, decision_ref=decision, clock_ms=lambda: ts)
        bound.write()
    assert inner.calls == []


@pytest.mark.parametrize("kind", ["async_method", "sync_awaitable"])
@pytest.mark.parametrize("outcome", ["COMMITTED", "FAILED", "cancelled"])
def test_awaitable_is_recorded_only_after_completion(kind, outcome):
    class AsyncClient:
        calls = 0

        async def perform(self):
            self.calls += 1
            if outcome == "FAILED":
                raise RuntimeError("write failed")
            if outcome == "cancelled":
                raise asyncio.CancelledError()
            return "written"

        if kind == "async_method":
            write = perform
        else:
            def write(self):
                return self.perform()

    inner = AsyncClient()
    bound = connector("test", writes={"write": ("write", lambda c: "scope")})(
        inner, decision_ref=synth_ref(), clock_ms=lambda: 1)
    pending = bound.write()
    try:
        assert bound.executions == []
        assert inner.calls == 0
    except BaseException:
        pending.close()
        raise
    if outcome == "COMMITTED":
        assert asyncio.run(pending) == "written"
    else:
        error = RuntimeError if outcome == "FAILED" else asyncio.CancelledError
        with pytest.raises(error):
            asyncio.run(pending)
    assert inner.calls == 1
    assert len(bound.executions) == 1
    assert bound.executions[0]["outcome"] == ("COMMITTED" if outcome == "COMMITTED" else "FAILED")


@pytest.mark.parametrize("mutation", ["mapping", "entry", "public_spec"])
def test_declared_write_binding_is_snapshot(mutation):
    spec = {"write": ["write", lambda c: "scope"]}
    factory = connector("test", writes=spec)
    bound = factory(Client(), decision_ref=synth_ref(), clock_ms=lambda: 1)
    if mutation == "mapping":
        spec.clear()
    elif mutation == "entry":
        spec["write"][0] = "other"
    else:
        try:
            factory.writes.clear()
        except (AttributeError, TypeError):
            pass  # A read-only public spec is also acceptable.
    assert bound.write() == "written"
    assert len(bound.executions) == 1
    assert bound.executions[0]["action_type"] == "test:write"
    later = factory(Client(), decision_ref=synth_ref(), clock_ms=lambda: 1)
    later.write()
    assert later.executions[0]["action_type"] == "test:write"


def test_execution_callback_cannot_rewrite_stored_evidence():
    def observer(record):
        record["outcome"] = "FAILED"
        record["scope"] = "other"

    bound = connector("test", writes={"write": ("write", lambda c: "scope")})(
        Client(), decision_ref=synth_ref(), clock_ms=lambda: 1, on_execution=observer)
    bound.write()
    record = bound.executions[0]
    assert record["outcome"] == "COMMITTED"
    assert record["execution_ref"] == execution_ref(
        record["decision_ref"], record["action_type"], record["scope"],
        record["outcome"], record["executed_at_ms"])
