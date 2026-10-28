"""Refund Receipt (lite) -- open, content-addressed refund references for the AlgoVoi substrate.

The lite, Apache-2.0 origination layer for AlgoVoi Refund Receipt. It content-addresses the
refund of a prior payment into a deterministic, recomputable ``refund_ref``:

    refund_ref = "sha256:" + SHA-256(JCS({refund_amount, refund_result, subject_ref}))

  * ``subject_ref``    -- the prior payment or decision being refunded (imported by hash; e.g. the
                         ``guardrail_ref`` of the pre-payment decision, a settlement ``binding_ref``,
                         or an original payment reference).
  * ``refund_result`` -- the categorical outcome. A closed enum: FULL, PARTIAL, REJECTED.
  * ``refund_amount`` -- the amount returned, as a string (e.g. "1000"; "0" for a REJECTED refund).

Because the result and amount are bound to the exact subject by hash, a refund cannot be silently
re-pointed to another payment, and neither the categorical outcome nor the amount can be changed
without the ``refund_ref`` diverging. This closes the lifecycle after settlement: the same
reference the decision produced is the one a refund points back to.

This is the LITE tier: content-addressed and offline-recomputable, no signature. The commercial
Refund Receipt issues Falcon-1024 (post-quantum) signed receipts carrying the refund provider,
timing, and jurisdiction flags, and closes the original payment across the settlement and
retention chains. Additive over the frozen substrate; no new crypto.
"""
from __future__ import annotations

from algovoi_substrate import sha256_jcs

__all__ = ["RefundReceiptError", "SHA256_PREFIX", "REFUND_RESULTS", "refund_ref", "verify"]

SHA256_PREFIX = "sha256:"
REFUND_RESULTS = ("FULL", "PARTIAL", "REJECTED")


class RefundReceiptError(ValueError):
    """Raised on a missing/non-string subject_ref or refund_amount, or a refund_result outside the enum."""


def refund_ref(subject_ref: str, refund_result: str, refund_amount: str) -> str:
    """Content-addressed refund reference: the refunded subject + result + amount go in, only the hash comes out."""
    if not isinstance(subject_ref, str) or not subject_ref:
        raise RefundReceiptError("subject_ref must be a non-empty string")
    if refund_result not in REFUND_RESULTS:
        raise RefundReceiptError(
            f"refund_result must be one of {REFUND_RESULTS}, got {refund_result!r}"
        )
    if not isinstance(refund_amount, str) or not refund_amount:
        raise RefundReceiptError("refund_amount must be a non-empty string")
    return SHA256_PREFIX + sha256_jcs(
        {"refund_amount": refund_amount, "refund_result": refund_result, "subject_ref": subject_ref}
    )


def verify(refund_ref_value: str, subject_ref: str, refund_result: str, refund_amount: str) -> bool:
    """True if (subject_ref, refund_result, refund_amount) recompute to refund_ref_value (else tamper/malformed)."""
    try:
        return refund_ref(subject_ref, refund_result, refund_amount) == refund_ref_value
    except RefundReceiptError:
        return False
