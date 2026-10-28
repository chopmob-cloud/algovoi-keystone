"""Payment Mandate (lite) -- open, content-addressed spend-authority references for the AlgoVoi substrate.

The lite, Apache-2.0 origination layer for AlgoVoi Payment Mandate. It content-addresses
the terms of a spend authority into a deterministic, recomputable ``mandate_ref``:

    mandate_ref = "sha256:" + SHA-256(JCS({cap, payer, period, revocation_state}))

  * ``payer``             -- who authorised the spend.
  * ``cap``              -- the per-period spending cap (as a string, e.g. "1000").
  * ``period``           -- the cap period (e.g. "monthly").
  * ``revocation_state`` -- the authority's current state (e.g. "active", "revoked").

This ``mandate_ref`` is exactly the spend authority that Spend Guardrail (lite) binds: an
agent platform pins the mandate by hash, then the pre-payment decision is bound to that
hash. Change the cap, the period, or the revocation state and the ``mandate_ref`` diverges,
so a decision made against one authority cannot be silently re-attributed to another.

This is the LITE tier: content-addressed and offline-recomputable, no signature. The
commercial Payment Mandate issues, verifies, and authorises charges against Falcon-1024
(post-quantum) signed mandates, checking every pull against the per-period cap. Additive
over the frozen substrate; no new crypto.
"""
from __future__ import annotations

from algovoi_substrate import sha256_jcs

__all__ = ["PaymentMandateError", "SHA256_PREFIX", "mandate_ref", "verify"]

SHA256_PREFIX = "sha256:"
_FIELDS = ("payer", "cap", "period", "revocation_state")


class PaymentMandateError(ValueError):
    """Raised on a missing or non-string mandate field."""


def mandate_ref(payer: str, cap: str, period: str, revocation_state: str) -> str:
    """Content-addressed spend-authority reference: the mandate terms go in, only the hash comes out."""
    values = {"cap": cap, "payer": payer, "period": period, "revocation_state": revocation_state}
    for name in _FIELDS:
        if not isinstance(values[name], str) or not values[name]:
            raise PaymentMandateError(f"{name} must be a non-empty string")
    return SHA256_PREFIX + sha256_jcs(values)


def verify(mandate_ref_value: str, payer: str, cap: str, period: str, revocation_state: str) -> bool:
    """True if (payer, cap, period, revocation_state) recompute to mandate_ref_value (else tamper/malformed)."""
    try:
        return mandate_ref(payer, cap, period, revocation_state) == mandate_ref_value
    except PaymentMandateError:
        return False
