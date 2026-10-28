"""
algovoi-execution-ref: decision-bound execution evidence + keystone binding.

A standalone app that implements execution_ref and binds the full keystone
chain. It depends ONLY on the substrate's JCS canonicalisation (sha256_jcs),
which is byte-stable and present in every substrate release, so this app runs
unchanged on substrate v0 (0.x) and v1 (1.x). An existing adopter gets
execution_ref and the keystone without upgrading their substrate.

    execution_ref = "sha256:" + SHA-256(JCS({decision_ref, action_type, scope,
                                            outcome, executed_at_ms}))

The keystone it binds:

    passport_ref -> mandate_ref -> policy_bound_ref
        -> decision_ref   = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))
        -> execution_ref  (above; decision-bound)
        -> trust_query_ref = "sha256:" + SHA-256(JCS({subject_refs, trust_outcome}))

Every reference is JCS (RFC 8785) + SHA-256, so the chain reproduces byte for
byte from raw fields with no issuer contact, identical on any substrate version.
"""
from __future__ import annotations

import re

# sha256_jcs is the one substrate primitive this app uses. It is present and
# byte-identical across substrate v0 (0.x) and v1 (1.x).
from algovoi_substrate import sha256_jcs

_SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

EXECUTION_OUTCOMES = ("COMMITTED", "SKIPPED", "FAILED", "REVERSED")
DECISION_VERDICTS = ("ALLOW", "DENY", "REFER")
TRUST_OUTCOMES = ("TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED")


class ExecutionRefError(ValueError):
    """Raised when inputs violate the substrate discipline."""


def _ref(field: str, value: object) -> str:
    if not isinstance(value, str) or not _SHA256_REF_RE.match(value):
        raise ExecutionRefError(f"{field} must be 'sha256:<lowercase 64-char hex>'")
    return value


def _nonempty(field: str, value: object) -> str:
    if not isinstance(value, str) or value == "":
        raise ExecutionRefError(f"{field} must be a non-empty string")
    return value


def _member(field: str, value: object, members: tuple[str, ...]) -> str:
    if value not in members:
        raise ExecutionRefError(f"{field} must be one of {members}, got {value!r}")
    return value


def _int_ms(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExecutionRefError("executed_at_ms must be an epoch-millisecond integer")
    if value < 0:
        raise ExecutionRefError("executed_at_ms must be non-negative")
    return value


def execution_ref(decision_ref: str, action_type: str, scope: str,
                  outcome: str, executed_at_ms: int) -> str:
    """execution_ref = "sha256:" + SHA-256(JCS(preimage)). Decision-bound."""
    return "sha256:" + sha256_jcs({
        "decision_ref": _ref("decision_ref", decision_ref),
        "action_type": _nonempty("action_type", action_type),
        "scope": _nonempty("scope", scope),
        "outcome": _member("outcome", outcome, EXECUTION_OUTCOMES),
        "executed_at_ms": _int_ms(executed_at_ms),
    })


def decision_ref(agent_ref: str, mandate_ref: str, policy_bound_ref: str, verdict: str) -> str:
    """The pre-payment decision reference (the keystone this execution binds to)."""
    return "sha256:" + sha256_jcs({
        "agent_ref": _ref("agent_ref", agent_ref),
        "mandate_ref": _ref("mandate_ref", mandate_ref),
        "policy_bound_ref": _ref("policy_bound_ref", policy_bound_ref),
        "verdict": _member("verdict", verdict, DECISION_VERDICTS),
    })


def trust_query_ref(subject_refs: list[str], trust_outcome: str) -> str:
    """A composite trust verdict over an ordered reference list."""
    if not isinstance(subject_refs, list) or not subject_refs:
        raise ExecutionRefError("subject_refs must be a non-empty list")
    refs = [_ref(f"subject_refs[{i}]", r) for i, r in enumerate(subject_refs)]
    return "sha256:" + sha256_jcs({
        "subject_refs": refs,
        "trust_outcome": _member("trust_outcome", trust_outcome, TRUST_OUTCOMES),
    })


def execution_binding(execution_ref: str, settlement_ref: str, retention_chain_ref: str) -> str:
    """Post-settlement accountability binding over an execution_ref.

    The execution-tier replacement for the action_ref settlement binding. Because
    execution_ref already encodes the committed outcome bound to its authorizing
    decision, it subsumes the old (action_ref + transition_hash) pair: one
    decision-bound reference instead of two.

        binding_ref = "sha256:" + SHA-256(JCS({execution_ref, settlement_ref, retention_chain_ref}))
    """
    return "sha256:" + sha256_jcs({
        "execution_ref": _ref("execution_ref", execution_ref),
        "settlement_ref": _ref("settlement_ref", settlement_ref),
        "retention_chain_ref": _ref("retention_chain_ref", retention_chain_ref),
    })


def bind_keystone(
    *,
    passport_ref: str,
    mandate_ref: str,
    policy_bound_ref: str,
    verdict: str,
    action_type: str,
    scope: str,
    outcome: str,
    executed_at_ms: int,
    trust_outcome: str,
) -> dict:
    """Bind an execution to the full keystone and return a self-describing record.

    The execution is bound to the exact decision the chain produced. Content
    address of the record is trust_query_ref. Identical bytes on any substrate
    version.
    """
    d_ref = decision_ref(passport_ref, mandate_ref, policy_bound_ref, verdict)
    e_ref = execution_ref(d_ref, action_type, scope, outcome, executed_at_ms)
    chain = [_ref("passport_ref", passport_ref), _ref("mandate_ref", mandate_ref),
             _ref("policy_bound_ref", policy_bound_ref), d_ref, e_ref]
    tq_ref = trust_query_ref(chain, trust_outcome)
    return {
        "canon_version": "jcs-rfc8785-v1",
        "type": "execution_keystone",
        "passport_ref": passport_ref,
        "mandate_ref": mandate_ref,
        "policy_bound_ref": policy_bound_ref,
        "verdict": verdict,
        "decision_ref": d_ref,
        "action_type": action_type,
        "scope": scope,
        "outcome": outcome,
        "executed_at_ms": executed_at_ms,
        "execution_ref": e_ref,
        "trust_outcome": trust_outcome,
        "trust_query_ref": tq_ref,
        "chain": chain,
    }


def verify_record(record: dict) -> bool:
    """Recompute decision_ref, execution_ref, trust_query_ref, and the chain from
    the record's raw fields; return True iff all match the carried values."""
    required = ("passport_ref", "mandate_ref", "policy_bound_ref", "verdict",
                "action_type", "scope", "outcome", "executed_at_ms", "trust_outcome")
    missing = [f for f in required if f not in record]
    if missing:
        raise ExecutionRefError(f"record missing required fields: {missing}")
    rebuilt = bind_keystone(**{f: record[f] for f in required})
    return all(record.get(k) == rebuilt[k]
               for k in ("decision_ref", "execution_ref", "trust_query_ref", "chain"))


__all__ = [
    "ExecutionRefError",
    "EXECUTION_OUTCOMES", "DECISION_VERDICTS", "TRUST_OUTCOMES",
    "execution_ref", "decision_ref", "trust_query_ref",
    "execution_binding", "bind_keystone", "verify_record",
]
