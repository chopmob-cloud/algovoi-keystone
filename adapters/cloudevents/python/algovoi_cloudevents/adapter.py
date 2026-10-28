"""algovoi-cloudevents -- emit an AlgoVoi keystone decision as a CloudEvents 1.0 event.

The content-addressed ``execution_ref`` is a natural CloudEvents ``id`` (deterministic, unique).
The keystone references live in the event ``data`` and the standard ``id`` / ``subject`` context
attributes. We do NOT invent CloudEvents context extension attributes for them: the event stays
spec-conformant and the producer's context-attribute space is untouched.

    execution_ref = "sha256:" + SHA-256(JCS(RFC 8785)({decision_ref, action_type, scope, outcome,
                                                       executed_at_ms}))

A consumer recomputes ``execution_ref`` from ``event["data"]`` with only JCS + SHA-256, no service
call, and confirms it equals the event ``id``. Apache-2.0.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from algovoi_substrate import sha256_jcs

SHA256_PREFIX = "sha256:"
SPEC_VERSION = "1.0"
TYPE_PREFIX = "co.algovoi.keystone"
STAGES = ("decision", "execution", "settlement", "cancellation", "refund", "trust_query")

__all__ = ["SHA256_PREFIX", "SPEC_VERSION", "TYPE_PREFIX", "STAGES",
           "execution_ref", "to_cloudevent", "verify_cloudevent_execution_ref"]


def execution_ref(decision_ref: str, action_type: str, scope: str, outcome: str,
                  executed_at_ms: int) -> str:
    """Recompute the decision-bound execution_ref (the content-addressed event identity)."""
    return SHA256_PREFIX + sha256_jcs({
        "decision_ref": decision_ref, "action_type": action_type, "scope": scope,
        "outcome": outcome, "executed_at_ms": int(executed_at_ms),
    })


def _rfc3339(ms: int) -> str:
    return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def to_cloudevent(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                  executed_at_ms: int, source: str, stage: str = "execution",
                  event_id: Optional[str] = None, agent_id: Optional[str] = None,
                  public_key_algorithm: Optional[str] = None,
                  trust: Optional[Mapping[str, Any]] = None,
                  drift: Optional[Mapping[str, Any]] = None,
                  scan: Optional[Mapping[str, Any]] = None,
                  trust_query_ref: Optional[str] = None,
                  settlement_ref: Optional[str] = None) -> dict:
    """Build a CloudEvents 1.0 event (structured JSON form) for a keystone decision.

    `source` is the producer URI-reference (e.g. did:web:... or an https URL). The event `id`
    defaults to the content-addressed execution_ref; `subject` is the decision_ref; the keystone
    refs and any producer signals (trust/drift/scan, public_key_algorithm, agent_id) go in `data`."""
    er = execution_ref(decision_ref, action_type, scope, outcome, int(executed_at_ms))
    data: dict = {
        "execution_ref": er, "decision_ref": decision_ref, "action_type": action_type,
        "scope": scope, "outcome": outcome, "executed_at_ms": int(executed_at_ms),
    }
    if agent_id is not None:
        data["agent_id"] = agent_id
    if public_key_algorithm is not None:
        data["public_key_algorithm"] = public_key_algorithm
    if trust is not None:
        data["trust"] = dict(trust)
    if drift is not None:
        data["drift"] = dict(drift)
    if scan is not None:
        data["scan"] = dict(scan)
    if trust_query_ref is not None:
        data["trust_query_ref"] = trust_query_ref
    if settlement_ref is not None:
        data["settlement_ref"] = settlement_ref
    return {
        "specversion": SPEC_VERSION,
        "type": f"{TYPE_PREFIX}.{stage}.v1",
        "source": source,
        "id": event_id or er,
        "subject": decision_ref,
        "time": _rfc3339(executed_at_ms),
        "datacontenttype": "application/json",
        "data": data,
    }


def verify_cloudevent_execution_ref(event: Mapping[str, Any]) -> bool:
    """Recompute execution_ref from event['data'] and confirm it matches data['execution_ref'].

    Independent of any AlgoVoi service; needs only JCS + SHA-256. Fail-closed on missing fields."""
    try:
        d = event["data"]
        recomputed = execution_ref(d["decision_ref"], d["action_type"], d["scope"],
                                   d["outcome"], int(d["executed_at_ms"]))
    except (KeyError, TypeError, ValueError):
        return False
    return recomputed == d.get("execution_ref")
