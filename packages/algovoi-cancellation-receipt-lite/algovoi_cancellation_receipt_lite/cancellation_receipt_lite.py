"""Cancellation Receipt (lite) -- open, content-addressed cancellation references for the AlgoVoi substrate.

The lite, Apache-2.0 origination layer for AlgoVoi Cancellation Receipt. It content-addresses
the cancellation of a spend authority into a deterministic, recomputable ``cancellation_ref``:

    cancellation_ref = "sha256:" + SHA-256(JCS({cancellation_reason, mandate_ref}))

  * ``mandate_ref``          -- the spend authority being cancelled (imported by hash; this is the
                               same ``mandate_ref`` Payment Mandate (lite) produces and Spend
                               Guardrail (lite) binds).
  * ``cancellation_reason`` -- why the authority was cancelled. A closed enum:
                               USER_REQUESTED, MERCHANT_REQUESTED, COMPLIANCE_TERMINATED, EXPIRED.

Because the reason is bound to the exact mandate by hash, a cancellation cannot be silently
re-pointed to a different authority, and the categorical reason cannot be swapped without the
``cancellation_ref`` diverging. This closes the lifecycle on the authority side: the same
``mandate_ref`` the pre-payment decision was checked against is the one a cancellation references.

This is the LITE tier: content-addressed and offline-recomputable, no signature. The commercial
Cancellation Receipt issues Falcon-1024 (post-quantum) signed receipts carrying the cancellation
provider, effective-from timing, and jurisdiction flags, and propagates the cancellation across
the settlement and retention chains. Additive over the frozen substrate; no new crypto.
"""
from __future__ import annotations

from algovoi_substrate import sha256_jcs

__all__ = ["CancellationReceiptError", "SHA256_PREFIX", "REASONS", "cancellation_ref", "verify"]

SHA256_PREFIX = "sha256:"
REASONS = ("USER_REQUESTED", "MERCHANT_REQUESTED", "COMPLIANCE_TERMINATED", "EXPIRED")


class CancellationReceiptError(ValueError):
    """Raised on a missing/non-string mandate_ref or a cancellation_reason outside the closed enum."""


def cancellation_ref(mandate_ref: str, cancellation_reason: str) -> str:
    """Content-addressed cancellation reference: the cancelled authority + reason go in, only the hash comes out."""
    if not isinstance(mandate_ref, str) or not mandate_ref:
        raise CancellationReceiptError("mandate_ref must be a non-empty string")
    if cancellation_reason not in REASONS:
        raise CancellationReceiptError(
            f"cancellation_reason must be one of {REASONS}, got {cancellation_reason!r}"
        )
    return SHA256_PREFIX + sha256_jcs(
        {"cancellation_reason": cancellation_reason, "mandate_ref": mandate_ref}
    )


def verify(cancellation_ref_value: str, mandate_ref: str, cancellation_reason: str) -> bool:
    """True if (mandate_ref, cancellation_reason) recompute to cancellation_ref_value (else tamper/malformed)."""
    try:
        return cancellation_ref(mandate_ref, cancellation_reason) == cancellation_ref_value
    except CancellationReceiptError:
        return False
