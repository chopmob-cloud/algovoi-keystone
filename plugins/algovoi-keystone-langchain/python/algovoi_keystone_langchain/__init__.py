"""algovoi-keystone-langchain -- carry an AlgoVoi keystone decision into a LangChain run trace.

A keystone decision's content-addressed ``execution_ref`` is attached to a LangChain run as
metadata and a tag, under the vendor namespace ``algovoi.keystone.*`` (never inside a LangChain
reserved field). Anyone reading the trace recomputes ``execution_ref`` from the run metadata alone
with only JCS (RFC 8785) + SHA-256, and confirms the agent's recorded action is consistent with the
decision that authorized it -- bound, not merely correlated.

Two surfaces:

* ``keystone_config(...)`` returns a RunnableConfig (a plain dict LangChain accepts) carrying the
  keystone metadata and tag, for ``chain.invoke(x, config=keystone_config(...))``.
* ``KeystoneCallbackHandler`` is an optional callback handler (needs the ``langchain`` extra) that
  exposes the same metadata for handlers-based wiring.

The core (``keystone_trace_metadata`` / ``verify_trace_execution_ref``) is framework-neutral.
Byte-identical to @algovoi/keystone-langchain (Node). Apache-2.0.
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
    executed_at_ms})). Integer epoch-ms hashed directly; byte-identical across the substrate."""
    return SHA256_PREFIX + sha256_jcs({
        "decision_ref": decision_ref,
        "action_type": action_type,
        "scope": scope,
        "outcome": outcome,
        "executed_at_ms": int(executed_at_ms),
    })


def keystone_trace_metadata(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                            executed_at_ms: int, agent_id: str | None = None,
                            trust_query_ref: str | None = None) -> dict:
    """The framework-neutral keystone trace attributes, all under ``algovoi.keystone.*``. The
    consumer recomputes ``execution_ref`` from these fields alone."""
    md = {
        _K_EXEC: execution_ref(decision_ref, action_type, scope, outcome, executed_at_ms),
        _K_DECISION: decision_ref,
        _K_ACTION: action_type,
        _K_SCOPE: scope,
        _K_OUTCOME: outcome,
        _K_TS: int(executed_at_ms),
    }
    if agent_id is not None:
        md[_K_AGENT] = agent_id
    if trust_query_ref is not None:
        md[_K_TQ] = trust_query_ref
    return md


def keystone_config(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                    executed_at_ms: int, agent_id: str | None = None,
                    trust_query_ref: str | None = None) -> dict:
    """A LangChain RunnableConfig (plain dict) that attaches the keystone metadata and an
    ``algovoi.keystone.execution_ref=...`` tag to a run, so the reference propagates to LangSmith
    and any tracer. Use as ``chain.invoke(x, config=keystone_config(...))``."""
    md = keystone_trace_metadata(decision_ref=decision_ref, action_type=action_type, scope=scope,
                                 outcome=outcome, executed_at_ms=executed_at_ms, agent_id=agent_id,
                                 trust_query_ref=trust_query_ref)
    return {"metadata": md, "tags": [f"{_K_EXEC}={md[_K_EXEC]}"]}


def verify_trace_execution_ref(metadata: Mapping[str, Any]) -> bool:
    """Recompute ``execution_ref`` from a run's keystone metadata and confirm it matches the carried
    value. Returns False on any missing field or mismatch."""
    try:
        recomputed = execution_ref(metadata[_K_DECISION], metadata[_K_ACTION], metadata[_K_SCOPE],
                                   metadata[_K_OUTCOME], int(metadata[_K_TS]))
        return recomputed == metadata[_K_EXEC]
    except Exception:
        return False


def make_callback_handler(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                          executed_at_ms: int, agent_id: str | None = None,
                          trust_query_ref: str | None = None):
    """Build a LangChain callback handler that carries the keystone metadata (needs the ``langchain``
    extra). The handler exposes ``.metadata`` and ``.tags`` for handlers-based wiring."""
    from langchain_core.callbacks import BaseCallbackHandler  # optional dependency

    md = keystone_trace_metadata(decision_ref=decision_ref, action_type=action_type, scope=scope,
                                 outcome=outcome, executed_at_ms=executed_at_ms, agent_id=agent_id,
                                 trust_query_ref=trust_query_ref)

    class KeystoneCallbackHandler(BaseCallbackHandler):
        """Surfaces the keystone trace metadata + tag for a run. Verifiable offline."""

        def __init__(self) -> None:
            self.metadata = dict(md)
            self.tags = [f"{_K_EXEC}={md[_K_EXEC]}"]

        def verify(self) -> bool:
            return verify_trace_execution_ref(self.metadata)

    return KeystoneCallbackHandler()


__all__ = [
    "__version__", "SHA256_PREFIX", "NAMESPACE", "OUTCOMES",
    "execution_ref", "keystone_trace_metadata", "keystone_config",
    "verify_trace_execution_ref", "make_callback_handler",
]
