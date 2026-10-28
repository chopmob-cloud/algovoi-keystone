"""algovoi-keystone-autogen -- carry an AlgoVoi keystone decision into an AutoGen conversation.

A keystone decision's content-addressed ``execution_ref`` is attached to an AutoGen message's
metadata, under the vendor namespace ``algovoi.keystone.*`` (never inside an AutoGen reserved
field). Anyone reading the conversation recomputes ``execution_ref`` from the message metadata alone
with only JCS (RFC 8785) + SHA-256, confirming the recorded action is consistent with the decision
that authorized it.

``keystone_message_metadata(...)`` returns the dict to merge into a message's ``metadata``;
``stamp_message(message, ...)`` does the merge in place. The core
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
    """Recompute ``execution_ref`` from message metadata and confirm it matches."""
    try:
        return execution_ref(metadata[_K_DECISION], metadata[_K_ACTION], metadata[_K_SCOPE],
                             metadata[_K_OUTCOME], int(metadata[_K_TS])) == metadata[_K_EXEC]
    except Exception:
        return False


def keystone_message_metadata(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                              executed_at_ms: int, agent_id: str | None = None,
                              trust_query_ref: str | None = None) -> dict:
    """The keystone trace metadata to merge into an AutoGen message's ``metadata`` field."""
    return keystone_trace_metadata(decision_ref=decision_ref, action_type=action_type, scope=scope,
                                   outcome=outcome, executed_at_ms=executed_at_ms, agent_id=agent_id,
                                   trust_query_ref=trust_query_ref)


def stamp_message(message: Any, *, decision_ref: str, action_type: str, scope: str, outcome: str,
                  executed_at_ms: int, agent_id: str | None = None,
                  trust_query_ref: str | None = None) -> Any:
    """Merge the keystone metadata into ``message``'s ``metadata`` (a dict on the message object, or
    a ``"metadata"`` key on a dict message), creating it if absent, and return the message."""
    md = keystone_message_metadata(decision_ref=decision_ref, action_type=action_type, scope=scope,
                                   outcome=outcome, executed_at_ms=executed_at_ms, agent_id=agent_id,
                                   trust_query_ref=trust_query_ref)
    meta = getattr(message, "metadata", None)
    if isinstance(meta, dict):
        meta.update(md)
    elif isinstance(message, dict):
        message.setdefault("metadata", {}).update(md)
    return message


__all__ = [
    "__version__", "SHA256_PREFIX", "NAMESPACE", "OUTCOMES",
    "execution_ref", "keystone_trace_metadata", "verify_trace_execution_ref",
    "keystone_message_metadata", "stamp_message",
]
