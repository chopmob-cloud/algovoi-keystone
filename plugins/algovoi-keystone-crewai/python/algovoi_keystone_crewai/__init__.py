"""algovoi-keystone-crewai -- carry an AlgoVoi keystone decision into a crewAI run.

A keystone decision's content-addressed ``execution_ref`` is recorded into a crew's run, under the
vendor namespace ``algovoi.keystone.*`` (never inside a crewAI reserved field). Anyone reading the
run recomputes ``execution_ref`` from the recorded metadata alone with only JCS (RFC 8785) +
SHA-256, confirming the agent's recorded action is consistent with the decision that authorized it.

``keystone_step_callback(...)`` returns a callable for ``Crew(step_callback=...)`` that records the
keystone metadata once per run into a sink (a list you own, or an internal default). The core
(``keystone_trace_metadata`` / ``verify_trace_execution_ref``) is framework-neutral. Apache-2.0.
"""
from __future__ import annotations

from typing import Any, Mapping

from algovoi_substrate import sha256_jcs

__version__ = "0.1.0"
SHA256_PREFIX = "sha256:"
NAMESPACE = "algovoi.keystone"
OUTCOMES = ("COMMITTED", "SKIPPED", "FAILED", "REVERSED")

_K_EXEC = f"{NAMESPACE}.execution_ref"
_K_DECISION = f"{NAMESPACE}.decision_ref"
_K_ACTION = f"{NAMESPACE}.action_type"
_K_SCOPE = f"{NAMESPACE}.scope"
_K_OUTCOME = f"{NAMESPACE}.outcome"
_K_TS = f"{NAMESPACE}.executed_at_ms"
_K_AGENT = f"{NAMESPACE}.agent_id"
_K_TQ = f"{NAMESPACE}.trust_query_ref"


def execution_ref(decision_ref: str, action_type: str, scope: str, outcome: str,
                  executed_at_ms: int) -> str:
    """execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope, outcome,
    executed_at_ms})). Byte-identical across the AlgoVoi substrate."""
    return SHA256_PREFIX + sha256_jcs({
        "decision_ref": decision_ref, "action_type": action_type, "scope": scope,
        "outcome": outcome, "executed_at_ms": int(executed_at_ms),
    })


def keystone_trace_metadata(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                            executed_at_ms: int, agent_id: str | None = None,
                            trust_query_ref: str | None = None) -> dict:
    """The framework-neutral keystone trace attributes, all under ``algovoi.keystone.*``."""
    md = {
        _K_EXEC: execution_ref(decision_ref, action_type, scope, outcome, executed_at_ms),
        _K_DECISION: decision_ref, _K_ACTION: action_type, _K_SCOPE: scope,
        _K_OUTCOME: outcome, _K_TS: int(executed_at_ms),
    }
    if agent_id is not None:
        md[_K_AGENT] = agent_id
    if trust_query_ref is not None:
        md[_K_TQ] = trust_query_ref
    return md


def verify_trace_execution_ref(metadata: Mapping[str, Any]) -> bool:
    """Recompute ``execution_ref`` from recorded keystone metadata and confirm it matches."""
    try:
        return execution_ref(metadata[_K_DECISION], metadata[_K_ACTION], metadata[_K_SCOPE],
                             metadata[_K_OUTCOME], int(metadata[_K_TS])) == metadata[_K_EXEC]
    except Exception:
        return False


def keystone_step_callback(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                           executed_at_ms: int, agent_id: str | None = None,
                           trust_query_ref: str | None = None, sink: list | None = None):
    """Return a crewAI ``step_callback`` that records the keystone trace metadata once per run.

    Use as ``Crew(agents=..., tasks=..., step_callback=keystone_step_callback(...))``. The metadata
    (under ``algovoi.keystone.*``) is appended to ``sink`` (a list you own) on the first step, so the
    crew's run carries the recomputable ``execution_ref``. The step output is passed through
    unchanged. Read it back with ``verify_trace_execution_ref(sink[0])``.
    """
    md = keystone_trace_metadata(decision_ref=decision_ref, action_type=action_type, scope=scope,
                                 outcome=outcome, executed_at_ms=executed_at_ms, agent_id=agent_id,
                                 trust_query_ref=trust_query_ref)
    target = sink if sink is not None else []
    state = {"recorded": False}

    def _callback(step_output: Any = None):
        if not state["recorded"]:
            target.append(dict(md))
            state["recorded"] = True
        return step_output

    _callback.keystone_metadata = dict(md)  # type: ignore[attr-defined]
    _callback.sink = target  # type: ignore[attr-defined]
    return _callback


__all__ = [
    "__version__", "SHA256_PREFIX", "NAMESPACE", "OUTCOMES",
    "execution_ref", "keystone_trace_metadata", "verify_trace_execution_ref",
    "keystone_step_callback",
]
