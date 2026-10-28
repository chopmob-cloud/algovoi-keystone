"""algovoi-otel-genai -- map an AlgoVoi keystone decision to OpenTelemetry gen_ai.agent.*
attributes, carrying ``execution_ref`` as an open, recomputable cross-producer key.

OpenTelemetry's gen_ai.agent.* attributes (open-telemetry/semantic-conventions-genai) are
producer-emitted and opaque: a consumer correlating across producers, or auditing one producer
without trusting it, has no recomputable handle. This adapter emits the standard attributes from
a keystone decision AND attaches ``algovoi.keystone.execution_ref`` -- decision-bound execution
evidence that any consumer recomputes from the span alone, with only JCS (RFC 8785) + SHA-256, no
service call and no AlgoVoi software beyond this hash.

    execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope, outcome,
                                             executed_at_ms}))

Unlike a bare-action correlation hash, execution_ref binds the action to the ``decision_ref`` that
authorized it: it shows consistency, not just correlation. Apache-2.0.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from algovoi_substrate import sha256_jcs

SHA256_PREFIX = "sha256:"
OUTCOMES = ("COMMITTED", "SKIPPED", "FAILED", "REVERSED")

__all__ = ["SHA256_PREFIX", "OUTCOMES", "execution_ref", "to_gen_ai_attributes",
           "verify_gen_ai_execution_ref"]


def execution_ref(decision_ref: str, action_type: str, scope: str, outcome: str,
                  executed_at_ms: int) -> str:
    """Recompute the decision-bound execution_ref (the open recomputable key)."""
    return SHA256_PREFIX + sha256_jcs({
        "decision_ref": decision_ref, "action_type": action_type, "scope": scope,
        "outcome": outcome, "executed_at_ms": int(executed_at_ms),
    })


def to_gen_ai_attributes(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                         executed_at_ms: int, agent_id: Optional[str] = None,
                         public_key_algorithm: Optional[str] = None,
                         trust: Optional[Mapping[str, Any]] = None,
                         drift: Optional[Mapping[str, Any]] = None,
                         scan: Optional[Mapping[str, Any]] = None,
                         trust_query_ref: Optional[str] = None) -> dict:
    """Emit OpenTelemetry gen_ai.agent.* attributes for a keystone decision.

    Producer signals (trust/drift/scan as {"score"/"verdict", "method"}, public_key_algorithm,
    agent_id) are passed through as the standard producer-emitted attributes. The adapter then
    attaches the recomputable handle: algovoi.keystone.execution_ref plus the preimage fields, so a
    consumer can re-derive and verify execution_ref from the span with no service call."""
    attrs: dict = {}
    if agent_id is not None:
        attrs["gen_ai.agent.id"] = agent_id
    if public_key_algorithm is not None:
        attrs["gen_ai.agent.public_key.algorithm"] = public_key_algorithm
    attrs["gen_ai.agent.capability"] = scope
    if trust is not None:
        attrs["gen_ai.agent.trust.score"] = float(trust["score"])
        if trust.get("method"):
            attrs["gen_ai.agent.trust.method"] = trust["method"]
    if drift is not None:
        attrs["gen_ai.agent.drift.score"] = float(drift["score"])
        if drift.get("method"):
            attrs["gen_ai.agent.drift.method"] = drift["method"]
    if scan is not None:
        attrs["gen_ai.agent.scan.verdict"] = scan["verdict"]
        if scan.get("method"):
            attrs["gen_ai.agent.scan.method"] = scan["method"]
    # the recomputable handle the producer-emitted attributes lack (decision-bound), emitted under
    # OUR OWN namespace (algovoi.keystone.*) -- NOT the controlled gen_ai.agent.* namespace, which is
    # governed by the OpenTelemetry GenAI SIG. Registering a standard gen_ai.agent.* attribute is a
    # separate working-group proposal; this adapter only adds vendor attributes under its own prefix.
    attrs["algovoi.keystone.execution_ref"] = execution_ref(decision_ref, action_type, scope, outcome, int(executed_at_ms))
    attrs["algovoi.keystone.decision_ref"] = decision_ref
    attrs["algovoi.keystone.action_type"] = action_type
    attrs["algovoi.keystone.scope"] = scope
    attrs["algovoi.keystone.outcome"] = outcome
    attrs["algovoi.keystone.executed_at_ms"] = int(executed_at_ms)
    if trust_query_ref is not None:
        attrs["algovoi.keystone.trust_query_ref"] = trust_query_ref
    return attrs


def verify_gen_ai_execution_ref(attrs: Mapping[str, Any]) -> bool:
    """Recompute execution_ref from the gen_ai.agent.* attributes on a span and confirm it matches.

    Independent of any AlgoVoi service; needs only the carried preimage fields + JCS + SHA-256.
    Returns False on any missing/malformed field (fail-closed)."""
    try:
        recomputed = execution_ref(
            attrs["algovoi.keystone.decision_ref"], attrs["algovoi.keystone.action_type"],
            attrs["algovoi.keystone.scope"], attrs["algovoi.keystone.outcome"],
            int(attrs["algovoi.keystone.executed_at_ms"]),
        )
    except (KeyError, TypeError, ValueError):
        return False
    return recomputed == attrs.get("algovoi.keystone.execution_ref")
