"""algovoi-keystone-adk -- carry an AlgoVoi keystone decision into a Google ADK run.

A keystone decision's content-addressed ``execution_ref`` is stamped into the ADK session state,
under the vendor namespace ``algovoi.keystone.*`` (never inside an ADK reserved field). Anyone
reading the run's events recomputes ``execution_ref`` from the state alone with only JCS (RFC 8785)
+ SHA-256, confirming the recorded action is consistent with the decision that authorized it.

``keystone_before_agent_callback(...)`` returns an ADK ``before_agent_callback`` that stamps the
keystone metadata into ``callback_context.state``; ``keystone_state_update(...)`` returns the dict
to merge into a ``State`` / ``tool_context.state`` yourself. The core
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
    """Recompute ``execution_ref`` from the stamped state and confirm it matches."""
    try:
        return execution_ref(metadata[_K_DECISION], metadata[_K_ACTION], metadata[_K_SCOPE],
                             metadata[_K_OUTCOME], int(metadata[_K_TS])) == metadata[_K_EXEC]
    except Exception:
        return False


def keystone_state_update(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                          executed_at_ms: int, agent_id: str | None = None,
                          trust_query_ref: str | None = None) -> dict:
    """The keystone trace metadata to merge into an ADK ``State`` / ``tool_context.state``."""
    return keystone_trace_metadata(decision_ref=decision_ref, action_type=action_type, scope=scope,
                                   outcome=outcome, executed_at_ms=executed_at_ms, agent_id=agent_id,
                                   trust_query_ref=trust_query_ref)


def keystone_before_agent_callback(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                                   executed_at_ms: int, agent_id: str | None = None,
                                   trust_query_ref: str | None = None):
    """Return an ADK ``before_agent_callback`` that stamps the keystone metadata into
    ``callback_context.state`` and returns None (does not skip the agent). Pass as
    ``LlmAgent(..., before_agent_callback=keystone_before_agent_callback(...))``."""
    md = keystone_state_update(decision_ref=decision_ref, action_type=action_type, scope=scope,
                               outcome=outcome, executed_at_ms=executed_at_ms, agent_id=agent_id,
                               trust_query_ref=trust_query_ref)

    def _callback(callback_context: Any):
        try:
            state = getattr(callback_context, "state", None)
            if state is not None:
                for k, v in md.items():
                    state[k] = v
        except Exception:
            pass
        return None

    _callback.keystone_metadata = dict(md)  # type: ignore[attr-defined]
    return _callback


__all__ = [
    "__version__", "SHA256_PREFIX", "NAMESPACE", "OUTCOMES",
    "execution_ref", "keystone_trace_metadata", "verify_trace_execution_ref",
    "keystone_state_update", "keystone_before_agent_callback",
]
