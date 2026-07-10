"""algovoi-keystone-agent -- the agentic behaviour layer for Keystone.

Define rules, triggers and behaviours as small declarative specs, deploy them in
an Engine, and test any behaviour at any stage offline. Composes with
algovoi-keystone-connect: connectors bind writes to decisions; behaviours gate
and react to those writes. Every behaviour firing produces a content-addressed
behaviour_ref, so an agent's own governance decisions are verifiable Keystone
records.

One primitive underneath everything:

    keystone_ref(payload) == "sha256:" + SHA-256(RFC 8785 JCS(payload))

so any party recomputes any behaviour_ref with a stock RFC 8785 implementation
and standard SHA-256, with no AlgoVoi software in their trust base.
"""
from __future__ import annotations

import time
from collections import namedtuple

try:  # single primitive + Report shared with the rest of Keystone
    from algovoi_keystone_connect import Report, keystone_ref, synth_ref
except Exception:  # pragma: no cover - standalone fallback, same primitive
    import hashlib

    import rfc8785

    def keystone_ref(payload):
        return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()

    def synth_ref(stage="decision", **fields):
        return keystone_ref({"__synth__": stage, **fields})

    class Report:
        def __init__(self):
            self.checks = []

        def add(self, name, passed, detail=""):
            self.checks.append((name, bool(passed), detail))

        @property
        def ok(self):
            return all(p for _, p, _ in self.checks) and bool(self.checks)

        def __repr__(self):
            lines = ["[%s] %s%s" % ("ok" if p else "FAIL", n, (" - " + d) if d else "")
                     for n, p, d in self.checks]
            return "\n".join(lines) + "\n=> %s" % ("PASS" if self.ok else "FAIL")

__all__ = [
    "VERDICTS", "Event", "Rule", "Trigger", "Behaviour", "Engine", "Denied",
    "rule", "trigger", "behaviour",
    "synth_event", "check_rule", "check_trigger", "check_behaviour",
    "keystone_ref", "synth_ref", "Report",
]

# BLOCK is strongest, ALLOW weakest -- see Engine.verdict.
VERDICTS = ("ALLOW", "FLAG", "BLOCK")
_STRENGTH = {"ALLOW": 0, "FLAG": 1, "BLOCK": 2}


def _now_ms():
    return int(time.time() * 1000)


def _jsonable(value):
    """Coerce an arbitrary value into RFC 8785-serialisable JSON types so a
    behaviour_ref never depends on un-canonicalisable state (bytes, tuples,
    opaque objects)."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, bytes):
        return {"__bytes__": len(value)}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return repr(value)


class Event(dict):
    """A Keystone record plus the chain `stage` it belongs to.

    Behaves like the underlying record dict, and also exposes each field as an
    attribute (``ev.amount``) for terse rules and triggers.
    """

    def __init__(self, stage, record=None, **fields):
        super().__init__(record or {})
        self.update(fields)
        self.stage = stage

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    @property
    def ref(self):
        """The ref of the originating record if it carries one, else a
        content-addressed ref over the whole event."""
        for k in ("execution_ref", "behaviour_ref", "trust_query_ref", "ref"):
            if self.get(k):
                return self[k]
        return keystone_ref({"stage": self.stage, "fields": _jsonable(dict(self))})


def _coerce_event(obj):
    if isinstance(obj, Event):
        return obj
    if isinstance(obj, tuple) and len(obj) == 2 and isinstance(obj[0], str):
        stage, record = obj
        return Event(stage, dict(record))
    if isinstance(obj, dict):
        stage = obj.get("stage") or ("execution" if "execution_ref" in obj else "event")
        return Event(stage, dict(obj))
    raise TypeError("cannot coerce %r into an Event" % type(obj).__name__)


Rule = namedtuple("Rule", "name predicate rule_ref")
Trigger = namedtuple("Trigger", "stage where trigger_ref")
Behaviour = namedtuple("Behaviour", "name on rule action behaviour_id")


def rule(name, predicate):
    """A pure rule: ``predicate(event)`` returns a verdict ("ALLOW"/"FLAG"/
    "BLOCK") or a bool (True == ALLOW, False == BLOCK)."""
    return Rule(name, predicate, keystone_ref({"kind": "rule", "name": name}))


def trigger(stage=None, where=None):
    """Matches an event when its stage equals `stage` (None == any stage) and
    ``where(event)`` is truthy (None == always)."""
    return Trigger(stage, where, keystone_ref({"kind": "trigger", "stage": stage}))


def behaviour(name, *, on, rule, action=None):
    """A deployable unit: when trigger `on` matches an event, evaluate `rule` to
    a verdict and run ``action(event, verdict)`` (optional)."""
    return Behaviour(
        name, on, rule, action,
        keystone_ref({"kind": "behaviour", "name": name,
                      "rule": rule.name, "stage": on.stage}),
    )


def _verdict_of(rule_obj, event):
    v = rule_obj.predicate(event)
    if v is True:
        return "ALLOW"
    if v is False:
        return "BLOCK"
    if v in VERDICTS:
        return v
    raise ValueError("rule %r returned %r; expected a verdict or bool"
                     % (rule_obj.name, v))


def _matches(trig, event):
    if trig.stage is not None and event.stage != trig.stage:
        return False
    if trig.where is not None and not trig.where(event):
        return False
    return True


class Denied(Exception):
    """Raised by a guarded write when a behaviour returns BLOCK. Carries the
    recorded firing so the block is auditable."""

    def __init__(self, record):
        self.record = record
        super().__init__("keystone-agent BLOCK by %r" % record.get("behaviour"))


class Engine:
    """Deploys a set of behaviours against a stream of events.

    Every firing appends a content-addressed behaviour_ref record to ``log``,
    bound to the engine's `decision_ref`, so the governance trail is itself a
    chain of verifiable Keystone records.
    """

    def __init__(self, behaviours, *, decision_ref, clock_ms=None, on_fire=None):
        self.behaviours = list(behaviours)
        self.decision_ref = decision_ref
        self._clock = clock_ms or _now_ms
        self._on_fire = on_fire
        self.log = []

    def dispatch(self, event):
        """Fire every behaviour whose trigger matches `event`; return the list of
        firing records (also appended to ``log``)."""
        event = event if isinstance(event, Event) else _coerce_event(event)
        fired = []
        for b in self.behaviours:
            if not _matches(b.on, event):
                continue
            verdict = _verdict_of(b.rule, event)
            executed_at_ms = self._clock()
            action_outcome = b.action(event, verdict) if b.action is not None else None
            record = {
                "decision_ref": self.decision_ref,
                "behaviour": b.name,
                "rule": b.rule.name,
                "stage": event.stage,
                "event_ref": event.ref,
                "verdict": verdict,
                "executed_at_ms": executed_at_ms,
            }
            if action_outcome is not None:
                record["action_outcome"] = _jsonable(action_outcome)
            record["behaviour_ref"] = keystone_ref(record)
            self.log.append(record)
            fired.append(record)
            if self._on_fire is not None:
                self._on_fire(record)
        return fired

    def verdict(self, event):
        """The strongest verdict across all behaviours that fire on `event`
        (BLOCK > FLAG > ALLOW); ALLOW when none fire."""
        fired = self.dispatch(event)
        if not fired:
            return "ALLOW"
        return max((r["verdict"] for r in fired), key=lambda v: _STRENGTH[v])

    def guard(self, connect_client, *, stage="execution"):
        """Wrap a keystone-connect client so each method call is dispatched as an
        event first. If any behaviour returns BLOCK, the call is denied (``Denied``
        raised) before it reaches the data plane; reads and non-matching calls
        pass straight through (their triggers simply do not match)."""
        engine = self

        class _Guarded:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                attr = getattr(self._inner, name)
                if not callable(attr):
                    return attr

                def _wrapped(*args, **kwargs):
                    ev = Event(stage, {
                        "method": name,
                        "args": _jsonable(args),
                        "kwargs": _jsonable(kwargs),
                        "decision_ref": engine.decision_ref,
                    })
                    if engine.verdict(ev) == "BLOCK":
                        raise Denied(engine.log[-1])
                    return attr(*args, **kwargs)

                return _wrapped

        return _Guarded(connect_client)


# --------------------------------------------------------------------------- #
# Test at any stage -- offline, deterministic, same Report shape as connect.
# --------------------------------------------------------------------------- #

def synth_event(stage="execution", **fields):
    """A content-addressed stand-in event for whatever precedes your behaviour,
    so you can test a rule or behaviour with no live gateway or real payments."""
    record = dict(fields)
    record.setdefault("decision_ref", synth_ref("decision"))
    return Event(stage, record)


def check_rule(rule_obj, cases):
    """`cases` = ``[(event, expected_verdict), ...]``. Asserts the rule evaluates,
    is deterministic, and matches every expected verdict."""
    r = Report()
    try:
        deterministic = all(
            _verdict_of(rule_obj, ev) == _verdict_of(rule_obj, ev) for ev, _ in cases
        )
        correct = all(_verdict_of(rule_obj, ev) == expected for ev, expected in cases)
    except Exception as exc:  # a broken rule fails the check, never crashes it
        r.add("evaluates to a verdict", False, repr(exc))
        return r
    r.add("evaluates to a verdict", True)
    r.add("deterministic", deterministic)
    r.add("matches expected verdicts", correct)
    return r


def check_trigger(trig, matching, non_matching=()):
    r = Report()
    r.add("fires on matching events", all(_matches(trig, _coerce_event(e)) for e in matching))
    r.add("ignores non-matching events",
          all(not _matches(trig, _coerce_event(e)) for e in non_matching))
    return r


def check_behaviour(bhv, events, *, decision_ref=None, expect=None, clock_ms=None):
    """Deploy `bhv` in a throwaway Engine over `events` and assert the Keystone
    properties. `expect` (optional) is a verdict every firing must equal."""
    r = Report()
    clk = clock_ms or (lambda: 1000)
    dref = decision_ref or synth_ref("decision")

    def _run(engine):
        out = []
        for ev in events:
            out.extend(engine.dispatch(ev if isinstance(ev, Event) else _coerce_event(ev)))
        return out

    try:
        fired = _run(Engine([bhv], decision_ref=dref, clock_ms=clk))
    except Exception as exc:
        r.add("dispatches without crashing", False, repr(exc))
        return r

    r.add("fires on its trigger", len(fired) > 0)

    recompute_ok = True
    for rec in fired:
        body = {k: v for k, v in rec.items() if k != "behaviour_ref"}
        if keystone_ref(body) != rec["behaviour_ref"]:
            recompute_ok = False
    r.add("behaviour_ref recomputes", recompute_ok)

    needed = ("decision_ref", "behaviour", "rule", "verdict", "event_ref", "executed_at_ms")
    r.add("self-describing record", all(all(k in rec for k in needed) for rec in fired))

    try:
        other = _run(Engine([bhv], decision_ref=synth_ref("decision", salt="other"), clock_ms=clk))
        bound = (len(other) == len(fired)
                 and all(a["behaviour_ref"] != b["behaviour_ref"] for a, b in zip(fired, other)))
    except Exception as exc:
        bound = False
        r.add("decision-bound", False, repr(exc))
    else:
        r.add("decision-bound", bound)

    if fired:
        tampered = dict(fired[0])
        tampered["verdict"] = "ALLOW" if tampered["verdict"] != "ALLOW" else "BLOCK"
        body = {k: v for k, v in tampered.items() if k != "behaviour_ref"}
        r.add("tamper-evident", keystone_ref(body) != fired[0]["behaviour_ref"])

    if expect is not None:
        r.add("verdict == %s" % expect, all(rec["verdict"] == expect for rec in fired))

    return r
