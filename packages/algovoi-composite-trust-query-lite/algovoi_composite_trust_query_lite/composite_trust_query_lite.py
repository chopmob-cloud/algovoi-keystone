"""Composite Trust Query (lite) -- open, content-addressed trust-verdict references for the AlgoVoi substrate.

The lite, Apache-2.0 origination layer for AlgoVoi Composite Trust Query. It content-addresses a
trust verdict over a set of pinned references into a deterministic, recomputable ``trust_query_ref``:

    trust_query_ref = "sha256:" + SHA-256(JCS({subject_refs, trust_outcome}))

  * ``subject_refs``  -- the ordered list of references the verdict was reached over, each imported
                        by hash (e.g. the passport_ref, mandate_ref, policy_bound_ref and
                        guardrail_ref of a decision chain). Order and membership are both
                        load-bearing.
  * ``trust_outcome`` -- the categorical verdict. A closed enum: TRUSTED, PROVISIONAL,
                        INSUFFICIENT_EVIDENCE, UNTRUSTED.

This caps the open lifecycle: one recomputable address binds a categorical trust answer to the
exact set of references it was computed over. Change which references were assessed, their order,
or the verdict, and the ``trust_query_ref`` diverges. The LITE tier content-addresses the binding
ONLY; the scoring and verification that produce the verdict stay commercial.

This is the LITE tier: content-addressed and offline-recomputable, no signature, no scoring engine.
The commercial Composite Trust Query walks the audit chain, checks every anchored receipt for
revocation/reversal/compliance termination under the asserted jurisdictions, and issues a
Falcon-1024 (post-quantum) signed verdict. Additive over the frozen substrate; no new crypto.
"""
from __future__ import annotations

from algovoi_substrate import sha256_jcs

__all__ = ["CompositeTrustQueryError", "SHA256_PREFIX", "TRUST_OUTCOMES", "trust_query_ref", "verify"]

SHA256_PREFIX = "sha256:"
TRUST_OUTCOMES = ("TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED")


class CompositeTrustQueryError(ValueError):
    """Raised on an empty/non-list subject_refs, a non-string member, or a trust_outcome outside the enum."""


def trust_query_ref(subject_refs, trust_outcome: str) -> str:
    """Content-addressed trust-verdict reference: the assessed references + verdict go in, only the hash comes out."""
    if not isinstance(subject_refs, (list, tuple)) or not subject_refs:
        raise CompositeTrustQueryError("subject_refs must be a non-empty list")
    if not all(isinstance(s, str) and s for s in subject_refs):
        raise CompositeTrustQueryError("each subject_ref must be a non-empty string")
    if trust_outcome not in TRUST_OUTCOMES:
        raise CompositeTrustQueryError(
            f"trust_outcome must be one of {TRUST_OUTCOMES}, got {trust_outcome!r}"
        )
    return SHA256_PREFIX + sha256_jcs(
        {"subject_refs": list(subject_refs), "trust_outcome": trust_outcome}
    )


def verify(trust_query_ref_value: str, subject_refs, trust_outcome: str) -> bool:
    """True if (subject_refs, trust_outcome) recompute to trust_query_ref_value (else tamper/malformed)."""
    try:
        return trust_query_ref(subject_refs, trust_outcome) == trust_query_ref_value
    except CompositeTrustQueryError:
        return False
