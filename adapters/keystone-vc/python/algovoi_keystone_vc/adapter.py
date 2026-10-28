"""algovoi-keystone-vc -- emit an AlgoVoi keystone decision as a W3C Verifiable Credential.

Produces a VC Data Model 2.0 credential whose ``credentialSubject`` carries the keystone
references. The content-addressed ``executionRef`` is the credential subject ``id``; a consumer
recomputes it from the subject with only JCS (RFC 8785) + SHA-256, with no service call, so the
credential is content-bound even before any signature suite is applied.

We use our OWN credential ``type`` (``KeystoneExecutionCredential``) and our own ``@context`` term,
not anyone else's vocabulary, so this needs no registration: a custom credential type is the
intended extension point of the VC Data Model.

    executionRef = "sha256:" + SHA-256(JCS(RFC 8785)({decision_ref, action_type, scope, outcome,
                                                      executed_at_ms}))

Signing the credential (a DataIntegrityProof, e.g. eddsa-jcs-2022) is the issuer's step; this open
adapter builds the credential and verifies the recomputable executionRef. Apache-2.0.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from algovoi_substrate import sha256_jcs

SHA256_PREFIX = "sha256:"
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
KEYSTONE_CONTEXT = "https://docs.algovoi.co.uk/contexts/keystone/v1"
CREDENTIAL_TYPE = "KeystoneExecutionCredential"

__all__ = ["SHA256_PREFIX", "VC_CONTEXT", "KEYSTONE_CONTEXT", "CREDENTIAL_TYPE",
           "execution_ref", "to_verifiable_credential", "verify_vc_execution_ref"]


def execution_ref(decision_ref: str, action_type: str, scope: str, outcome: str,
                  executed_at_ms: int) -> str:
    """Recompute the decision-bound execution_ref (the credential's content-addressed subject id)."""
    return SHA256_PREFIX + sha256_jcs({
        "decision_ref": decision_ref, "action_type": action_type, "scope": scope,
        "outcome": outcome, "executed_at_ms": int(executed_at_ms),
    })


def _rfc3339(ms: int) -> str:
    return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def to_verifiable_credential(*, decision_ref: str, action_type: str, scope: str, outcome: str,
                             executed_at_ms: int, issuer: str, credential_id: Optional[str] = None,
                             agent_id: Optional[str] = None, public_key_algorithm: Optional[str] = None,
                             trust: Optional[Mapping[str, Any]] = None,
                             drift: Optional[Mapping[str, Any]] = None,
                             scan: Optional[Mapping[str, Any]] = None,
                             trust_query_ref: Optional[str] = None,
                             settlement_ref: Optional[str] = None) -> dict:
    """Build an unsigned W3C VC (Data Model 2.0) for a keystone decision.

    ``issuer`` is the issuer DID or URL. The credentialSubject id is the content-addressed
    executionRef; the keystone refs and any producer signals are subject claims."""
    er = execution_ref(decision_ref, action_type, scope, outcome, int(executed_at_ms))
    subject: dict = {
        "id": er, "executionRef": er, "decisionRef": decision_ref, "actionType": action_type,
        "scope": scope, "outcome": outcome, "executedAtMs": int(executed_at_ms),
    }
    if agent_id is not None:
        subject["agentId"] = agent_id
    if public_key_algorithm is not None:
        subject["publicKeyAlgorithm"] = public_key_algorithm
    if trust is not None:
        subject["trustScore"] = float(trust["score"])
        if trust.get("method"):
            subject["trustMethod"] = trust["method"]
    if drift is not None:
        subject["driftScore"] = float(drift["score"])
        if drift.get("method"):
            subject["driftMethod"] = drift["method"]
    if scan is not None:
        subject["scanVerdict"] = scan["verdict"]
        if scan.get("method"):
            subject["scanMethod"] = scan["method"]
    if trust_query_ref is not None:
        subject["trustQueryRef"] = trust_query_ref
    if settlement_ref is not None:
        subject["settlementRef"] = settlement_ref
    vc: dict = {
        "@context": [VC_CONTEXT, KEYSTONE_CONTEXT],
        "type": ["VerifiableCredential", CREDENTIAL_TYPE],
        "issuer": issuer,
        "validFrom": _rfc3339(executed_at_ms),
        "credentialSubject": subject,
    }
    if credential_id is not None:
        vc["id"] = credential_id
    return vc


def verify_vc_execution_ref(vc: Mapping[str, Any]) -> bool:
    """Recompute executionRef from the credentialSubject and confirm it matches (and equals the
    subject id). Independent of any AlgoVoi service; JCS + SHA-256 only. Fail-closed."""
    try:
        s = vc["credentialSubject"]
        recomputed = execution_ref(s["decisionRef"], s["actionType"], s["scope"],
                                   s["outcome"], int(s["executedAtMs"]))
    except (KeyError, TypeError, ValueError):
        return False
    return recomputed == s.get("executionRef") == s.get("id")
