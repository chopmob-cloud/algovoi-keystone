"""Compliance Gate (lite) -- open, content-addressed compliance decisions for the AlgoVoi substrate.

The lite, Apache-2.0 origination layer for AlgoVoi Compliance Gate. You bring a
categorical screening verdict (ALLOW / REFER / DENY) from your own sanctions / PEP /
AML provider; this binds it to a no-PII payer reference and to a pinned subject ref
(a policy_bound_ref, settlement-action binding_ref, or retention_chain_ref -- imported
by hash) into a deterministic, recomputable ``gate_ref``. No PII leaves; the address
goes in, only its hash comes out.

    payer_ref = "sha256:" + SHA-256(JCS({address, network}))
    gate_ref  = "sha256:" + SHA-256(JCS({payer_ref, subject_ref, verdict}))

Because the verdict is bound to the subject by hash, a decision made under one policy
snapshot (a policy_bound_ref) does NOT recompute under a rotated policy -- the verdict
is provably tied to the policy in force when it was made.

This is the LITE tier: content-addressed and offline-recomputable, no signature. The
commercial Compliance Gate (v2) adds Falcon-1024 post-quantum signing, the maintained
verifier, and the Proofs (zero-knowledge) layer. Additive over the frozen substrate.
"""
from __future__ import annotations

import re

from algovoi_substrate import sha256_jcs

__all__ = ["VERDICTS", "ComplianceGateError", "SHA256_PREFIX", "payer_ref", "gate_ref", "verify"]

VERDICTS = ("ALLOW", "REFER", "DENY")
SHA256_PREFIX = "sha256:"
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ComplianceGateError(ValueError):
    """Raised on an invalid verdict, a malformed reference, or a missing field."""


def _require_ref(name: str, value: str) -> None:
    if not isinstance(value, str) or not _REF_RE.match(value):
        raise ComplianceGateError(f'{name} must be a "sha256:"-prefixed 64-hex reference')


def payer_ref(network: str, address: str) -> str:
    """Content-addressed, no-PII payer reference: the address goes in, only its hash comes out."""
    if not isinstance(network, str) or not network:
        raise ComplianceGateError("network must be a non-empty string")
    if not isinstance(address, str) or not address:
        raise ComplianceGateError("address must be a non-empty string")
    return SHA256_PREFIX + sha256_jcs({"address": address, "network": network})


def gate_ref(verdict: str, payer_ref: str, subject_ref: str) -> str:  # noqa: A002 - public param name
    """Bind a categorical verdict to a no-PII payer ref and a pinned subject ref."""
    if verdict not in VERDICTS:
        raise ComplianceGateError(f"verdict must be one of {VERDICTS}, got {verdict!r}")
    _require_ref("payer_ref", payer_ref)
    _require_ref("subject_ref", subject_ref)
    return SHA256_PREFIX + sha256_jcs(
        {"payer_ref": payer_ref, "subject_ref": subject_ref, "verdict": verdict}
    )


def verify(gate_ref_value: str, verdict: str, payer_ref_value: str, subject_ref: str) -> bool:
    """True if (verdict, payer_ref, subject_ref) recompute to gate_ref_value (else tamper/malformed)."""
    try:
        return gate_ref(verdict, payer_ref_value, subject_ref) == gate_ref_value
    except ComplianceGateError:
        return False
