"""algovoi-keystone-connect -- build and test Keystone bolt-ons with almost no boilerplate.

Two halves:

* **build** -- ``connector(prefix, writes=...)`` turns a data-plane connector from ~130 lines of
  wrapper class into a declarative spec. The returned factory wraps any client, binds each declared
  write to a ``decision_ref``, and emits a self-describing ``execution_ref`` record that drops
  straight into ``algovoi-keystone-validate``.

* **test at any stage** -- ``synth_ref(stage)`` gives a content-addressed stand-in for whatever
  precedes your bolt-on, and ``check_connector`` / ``check_ref_builder`` run the conformance battery
  (recompute, decision-bound, tamper-evident, self-describing shape, predecessor-binding) so a
  bolt-on can be verified at any stage of the chain -- passport, mandate, policy, decision,
  execution, trust_query -- in isolation, with no live gateway.

Everything reduces to one primitive: ``ref = "sha256:" + SHA-256(RFC 8785 JCS(payload))``. No magic,
no AlgoVoi software in the trust base. Apache-2.0.
"""
from __future__ import annotations

import hashlib
import time
from collections import namedtuple
from typing import Any, Callable

import rfc8785
from algovoi_execution_ref import EXECUTION_OUTCOMES, execution_ref

__all__ = [
    "keystone_ref",
    "connector",
    "Call",
    "synth_ref",
    "check_connector",
    "check_ref_builder",
    "Report",
    "EXECUTION_OUTCOMES",
]
__version__ = "0.1.0"


def keystone_ref(payload: Any) -> str:
    """The one primitive behind every stage: ``"sha256:" + SHA-256(RFC 8785 JCS(payload))``.

    Recomputable by anyone with a stock RFC 8785 implementation and standard SHA-256.
    """
    return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


# ---------------------------------------------------------------------------
# build: the connector factory (execution stage)
# ---------------------------------------------------------------------------

# A wrapped write call. ``scope`` functions receive this; read ``kwargs``/``args`` for per-call
# values and ``client`` for fixed attributes (a container name, a queue entity, ...).
Call = namedtuple("Call", "args kwargs client")


class _Bound:
    """A drop-in wrapper produced by ``connector(...)``. Attribute access falls through to the
    wrapped client; declared write methods are bound to the keystone."""

    def __init__(self, client: Any, prefix: str, writes: dict, decision_ref: str,
                 clock_ms: Callable[[], int] | None, on_execution: Callable[[dict], None] | None):
        if not (isinstance(decision_ref, str) and decision_ref):
            raise ValueError("decision_ref must be a non-empty string")
        self._client = client
        self._prefix = prefix
        self._writes = writes
        self._decision_ref = decision_ref
        self._clock = clock_ms or (lambda: int(time.time() * 1000))
        self._on = on_execution
        self.executions: list[dict] = []
        self.execution_ref: str | None = None

    def _record(self, action: str, scope: str, outcome: str, ts: int) -> dict:
        action_type = f"{self._prefix}:{action}"
        ref = execution_ref(self._decision_ref, action_type, scope, outcome, ts)
        rec = {"decision_ref": self._decision_ref, "scope": scope, "action_type": action_type,
               "outcome": outcome, "executed_at_ms": ts, "execution_ref": ref}
        self.execution_ref = ref
        self.executions.append(rec)
        if self._on:
            self._on(rec)
        return rec

    def _wrap(self, name: str, action: str, scope_fn: Callable[[Call], str]) -> Callable:
        fn = getattr(self._client, name)

        def caller(*args: Any, **kwargs: Any) -> Any:
            scope = str(scope_fn(Call(args, kwargs, self._client)) or "")
            ts = self._clock()
            try:
                result = fn(*args, **kwargs)
            except Exception:
                self._record(action, scope, "FAILED", ts)
                raise
            self._record(action, scope, "COMMITTED", ts)
            return result

        return caller

    def __getattr__(self, name: str) -> Any:
        writes = self.__dict__.get("_writes", {})
        spec = writes.get(name)
        if spec is not None:
            return self._wrap(name, spec[0], spec[1])
        client = self.__dict__.get("_client")
        if client is None:
            raise AttributeError(name)
        return getattr(client, name)


def connector(prefix: str, *, writes: dict) -> Callable:
    """Build a data-plane connector from a declarative spec.

    ``prefix``  -- the ``action_type`` namespace (e.g. ``"s3"`` -> ``s3:put``).
    ``writes``  -- ``{method_name: (action, scope_fn)}`` where ``scope_fn(call)`` returns the scope
                   string; ``call`` is a ``Call(args, kwargs, client)``.

    Returns a factory ``f(client, *, decision_ref, clock_ms=None, on_execution=None)`` that yields a
    drop-in wrapper. ``f.tamper_detected(claimed_ref, decision_ref=, action=, scope=, executed_at_ms=,
    outcome=)`` recomputes and checks any emitted record.
    """
    if not (isinstance(prefix, str) and prefix):
        raise ValueError("prefix must be a non-empty string")
    if not writes:
        raise ValueError("writes must map at least one method to (action, scope_fn)")

    def factory(client: Any, *, decision_ref: str, clock_ms: Callable[[], int] | None = None,
                on_execution: Callable[[dict], None] | None = None) -> _Bound:
        return _Bound(client, prefix, writes, decision_ref, clock_ms, on_execution)

    def tamper_detected(claimed_ref: str, *, decision_ref: str, action: str, scope: str,
                        outcome: str, executed_at_ms: int) -> bool:
        try:
            return execution_ref(decision_ref, f"{prefix}:{action}", scope, outcome,
                                 executed_at_ms) != claimed_ref
        except Exception:
            return True

    factory.prefix = prefix
    factory.writes = writes
    factory.tamper_detected = tamper_detected
    return factory


# ---------------------------------------------------------------------------
# test at any stage: synthetic upstream + conformance battery
# ---------------------------------------------------------------------------

def synth_ref(stage: str = "decision", **fields: Any) -> str:
    """A deterministic, content-addressed stand-in for an upstream stage, so a bolt-on can be tested
    in isolation. ``stage`` is any chain stage name (passport, mandate, policy, decision, execution,
    trust_query, ...). Extra ``fields`` vary the ref."""
    payload = {"stage": stage}
    payload.update(fields)
    return keystone_ref(payload)


class Report:
    """A conformance report: a list of (name, passed, detail) checks and an ``ok`` roll-up."""

    def __init__(self) -> None:
        self.checks: list[tuple] = []

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append((name, bool(passed), detail))

    @property
    def ok(self) -> bool:
        return all(p for _, p, _ in self.checks) and bool(self.checks)

    def __repr__(self) -> str:
        lines = ["[%s] %s%s" % ("ok" if p else "FAIL", n, (" - " + d) if d else "")
                 for n, p, d in self.checks]
        return "\n".join(lines) + "\n=> %s" % ("PASS" if self.ok else "FAIL")


def _recomputes(r: dict) -> bool:
    """True if a record's fields recompute to its claimed execution_ref. A malformed record (raising
    inputs, missing keys) counts as False, never an exception -- the harness must not crash on a
    broken bolt-on."""
    try:
        return r["execution_ref"] == execution_ref(r["decision_ref"], r["action_type"], r["scope"],
                                                    r["outcome"], r["executed_at_ms"])
    except Exception:
        return False


def _scope_mutation_changes_ref(r: dict) -> bool:
    """True if mutating the scope changes the recomputed ref (tamper-evidence). Malformed -> False."""
    try:
        return execution_ref(r["decision_ref"], r["action_type"], str(r["scope"]) + "X", r["outcome"],
                             r["executed_at_ms"]) != r["execution_ref"]
    except Exception:
        return False


def check_connector(factory: Callable, client: Any, calls: list, *,
                    decision_ref: str | None = None) -> Report:
    """Conformance-test a connector (execution stage).

    ``factory`` -- the value returned by ``connector(...)``.
    ``client``  -- a client double (or real client) to drive.
    ``calls``   -- ``[(method_name, kwargs_dict), ...]`` to execute.

    Checks: records emitted, recompute, self-describing shape, decision-bound, tamper-evident.
    """
    dr = decision_ref or synth_ref("decision")
    ts = 1700000000000
    rep = Report()
    c = factory(client, decision_ref=dr, clock_ms=lambda: ts)
    for name, kwargs in calls:
        getattr(c, name)(**kwargs)
    recs = list(c.executions)
    rep.add("records emitted", len(recs) == len(calls), "%d/%d" % (len(recs), len(calls)))
    core = ("decision_ref", "scope", "action_type", "outcome", "executed_at_ms", "execution_ref")
    rep.add("self-describing record shape", bool(recs) and all(all(k in r for k in core) for r in recs))
    rep.add("recompute (fields -> execution_ref)", bool(recs) and all(_recomputes(r) for r in recs))
    # decision-bound: same calls under a different decision -> every ref changes
    try:
        c2 = factory(client, decision_ref=synth_ref("decision", alt=True), clock_ms=lambda: ts)
        for name, kwargs in calls:
            getattr(c2, name)(**kwargs)
        db = bool(recs) and all(a["execution_ref"] != b["execution_ref"]
                                for a, b in zip(recs, c2.executions))
    except Exception:
        db = False
    rep.add("decision-bound (swap decision -> refs change)", db)
    # tamper-evident: mutate scope -> recompute no longer matches
    rep.add("tamper-evident (mutate scope -> mismatch)",
            bool(recs) and all(_scope_mutation_changes_ref(r) for r in recs))
    return rep


def check_ref_builder(build: Callable[[Any], str], payload: dict, *,
                      prev_field: str | None = None) -> Report:
    """Conformance-test a bolt-on that builds a ref at ANY stage (passport / mandate / policy /
    decision / execution / trust_query).

    ``build``      -- ``build(payload) -> "sha256:..."``.
    ``payload``    -- a representative input.
    ``prev_field`` -- optional key in ``payload`` holding the predecessor stage's ref; if given,
                      checks the bolt-on is bound to its predecessor.

    Checks: returns a sha256 ref, deterministic, content-addressed, tamper-evident, and (optionally)
    predecessor-bound.
    """
    rep = Report()

    def _b(p: Any) -> Any:
        try:
            return build(p)
        except Exception:
            return None

    ref = _b(payload)
    rep.add("returns a sha256: ref",
            isinstance(ref, str) and ref.startswith("sha256:") and len(ref) == 71)
    if not isinstance(ref, str):
        return rep   # can't test further if it does not even build
    rep.add("deterministic (same payload -> same ref)", _b(payload) == ref)
    rep.add("content-addressed (ref == sha256(jcs(payload)))", ref == keystone_ref(payload))
    if payload:
        k = next(iter(payload))
        tam = dict(payload)
        tam[k] = tam[k] + "__x" if isinstance(tam[k], str) else "__tampered"
        t = _b(tam)
        rep.add("tamper-evident (mutate a field -> different valid ref)",
                isinstance(t, str) and t != ref)
    if prev_field is not None:
        present = prev_field in payload
        rep.add("chains to predecessor (prev_field present)", present,
                "" if present else "prev_field=%r not in payload" % prev_field)
        if present:
            p2 = dict(payload)
            p2[prev_field] = synth_ref("predecessor", alt=True)
            p = _b(p2)
            rep.add("predecessor-bound (change predecessor -> different valid ref)",
                    isinstance(p, str) and p != ref)
    return rep
