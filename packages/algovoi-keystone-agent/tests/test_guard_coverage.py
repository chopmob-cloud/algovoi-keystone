"""A governance deployment that cannot ever fire must not look like governance.

The documented way to gate writes is ``rt.bind(client, behaviours=[cap_charges(500)])``
(runtime module docstring). ``cap_charges`` triggers on stage ``spend_decision``;
``Engine.guard`` dispatches at stage ``execution``. Those never intersect, so the
behaviour is silently dead and every write passes unbounded.
"""
import pytest

from algovoi_keystone_agent import Engine, check_guard_coverage
from algovoi_keystone_agent.library import cap_charges, deny_writes_to
from algovoi_keystone_connect import connector, keystone_ref


class FakeS3:
    def __init__(self):
        self.puts = []

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        return {"ETag": "e"}


def _connector():
    return connector("s3", writes={
        "put_object": ("put", lambda c: c.kwargs["Bucket"] + "/" + c.kwargs["Key"]),
    })


def _engine(behaviours_list, stage="execution"):
    return Engine(behaviours_list, decision_ref=keystone_ref({"grant": 1}),
                  clock_ms=lambda: 1)


def test_documented_cap_charge_deployment_actually_gates_a_write():
    """The exact deployment in the runtime docstring must not silently pass writes.

    `cap_charges` watches `spend_decision`; a guard dispatches `execution`. Building
    that guard must fail loudly rather than install a no-op gate.
    """
    client = _connector()(FakeS3(), decision_ref=keystone_ref({"grant": 1}))
    with pytest.raises(ValueError, match="never fire"):
        _engine([cap_charges(500)]).guard(client)


def test_deliberate_inert_deployment_is_opt_in_and_still_writes():
    """`allow_inert=True` is the explicit escape hatch: it works, and it warns."""
    inner = FakeS3()
    client = _connector()(inner, decision_ref=keystone_ref({"grant": 1}))
    guarded = _engine([cap_charges(500)]).guard(client, allow_inert=True)
    guarded.put_object(Bucket="receipts", Key="r1", amount=999_999)
    assert len(inner.puts) == 1  # ungated by design, and the caller said so


def test_correctly_staged_behaviour_blocks_the_write():
    """A behaviour for the guard's own stage does gate the write."""
    inner = FakeS3()
    client = _connector()(inner, decision_ref=keystone_ref({"grant": 1}))
    guarded = _engine([deny_writes_to("Bucket", ["locked"])]).guard(client)
    guarded.put_object(Bucket="receipts", Key="r1")
    assert len(inner.puts) == 1
    with pytest.raises(Exception) as exc:
        guarded.put_object(Bucket="locked", Key="r2")
    assert exc.type.__name__ == "Denied"
    assert len(inner.puts) == 1


def test_guard_coverage_reports_a_behaviour_that_can_never_fire():
    """A stage mismatch between triggers and the dispatch stage is a fail-open."""
    report = check_guard_coverage([cap_charges(500)], stage="execution")
    assert not report.ok
    failing = [(name, detail) for name, ok, detail in report.checks if not ok]
    assert any("never fire" in (name + detail) for name, detail in failing)


def test_guard_coverage_passes_when_every_behaviour_can_fire():
    report = check_guard_coverage(
        [deny_writes_to("Bucket", ["locked"])], stage="execution")
    assert report.ok, report


def test_guard_coverage_accepts_wildcard_stage_triggers():
    """A trigger with stage=None matches any stage, so it can always fire."""
    from algovoi_keystone_agent import behaviour, rule, trigger

    any_stage = behaviour("any", on=trigger(stage=None), rule=rule("allow", lambda ev: "ALLOW"))
    assert check_guard_coverage([any_stage], stage="execution").ok
