"""Agent Passport (lite) -- open, content-addressed agent identity references for the AlgoVoi substrate.

The lite, Apache-2.0 origination layer for AlgoVoi Agent Passport. It content-addresses
the public fields of an agent credential into a deterministic, recomputable ``passport_ref``:

    passport_ref = "sha256:" + SHA-256(JCS({agent_id, issuer, scope, validity_window}))

  * ``agent_id``         -- the agent identity the credential is for.
  * ``issuer``           -- who issued it (for example a DID).
  * ``scope``            -- what the agent is permitted to do.
  * ``validity_window``  -- the period the credential is valid for.

This ``passport_ref`` is exactly the ``agent_ref`` that Spend Guardrail (lite) binds: an
agent platform pins the passport by hash, then the pre-payment decision is bound to that
hash. Change any field and the ``passport_ref`` diverges, so a decision made for one agent
credential cannot be silently re-attributed to another.

This is the LITE tier: content-addressed and offline-recomputable, no signature. The
commercial Agent Passport issues and verifies Falcon-1024 (post-quantum) trust credentials,
binds spend limits, and supports revocation. Additive over the frozen substrate; no new crypto.
"""
from __future__ import annotations

from algovoi_substrate import sha256_jcs

__all__ = ["AgentPassportError", "SHA256_PREFIX", "passport_ref", "verify"]

SHA256_PREFIX = "sha256:"
_FIELDS = ("agent_id", "issuer", "scope", "validity_window")


class AgentPassportError(ValueError):
    """Raised on a missing or non-string passport field."""


def passport_ref(agent_id: str, issuer: str, scope: str, validity_window: str) -> str:
    """Content-addressed agent identity reference: the credential's public fields go in, only the hash comes out."""
    values = {"agent_id": agent_id, "issuer": issuer, "scope": scope, "validity_window": validity_window}
    for name in _FIELDS:
        if not isinstance(values[name], str) or not values[name]:
            raise AgentPassportError(f"{name} must be a non-empty string")
    return SHA256_PREFIX + sha256_jcs(values)


def verify(passport_ref_value: str, agent_id: str, issuer: str, scope: str, validity_window: str) -> bool:
    """True if (agent_id, issuer, scope, validity_window) recompute to passport_ref_value (else tamper/malformed)."""
    try:
        return passport_ref(agent_id, issuer, scope, validity_window) == passport_ref_value
    except AgentPassportError:
        return False
