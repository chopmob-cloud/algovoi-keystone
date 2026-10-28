"""Spend Guardrail (lite) -- open, content-addressed pre-payment decisions for the AlgoVoi substrate.

The lite, Apache-2.0 origination layer for AlgoVoi Spend Guardrail. One call an agent
platform makes BEFORE executing a payment: bind a categorical ALLOW / DENY decision to
the agent it was made for, the spend authority it was made against, and the policy in
force -- each imported by hash -- into a deterministic, recomputable ``guardrail_ref``.
Moves no funds. The decision is the whole pre-payment chain in one content address:

    guardrail_ref = "sha256:" + SHA-256(JCS({agent_ref, mandate_ref, policy_bound_ref, verdict}))

  * ``agent_ref``        -- the agent the decision was made for (a passport_ref).
  * ``mandate_ref``      -- the spend authority it was checked against (a mandate_ref).
  * ``policy_bound_ref`` -- the platform policy snapshot in force (from algovoi-policy-binding).
  * ``verdict``          -- the gate decision, a closed enumeration {ALLOW, DENY}.

Because the decision is bound to the policy by hash, an ALLOW made under one policy
snapshot does NOT recompute under a rotated policy -- the verdict is provably tied to
the agent, the authority, and the policy in force when it was made. Swap any input and
the guardrail_ref diverges.

This is the LITE tier: content-addressed and offline-recomputable, no signature. The
commercial Spend Guardrail adds Falcon-1024 post-quantum signing on the decision
receipt, the maintained verifier, and the full authorization stack (Agent Passport +
Payment Mandate enforcement). Additive over the frozen substrate; no new crypto.
"""
from __future__ import annotations

import re

from algovoi_substrate import sha256_jcs

__all__ = ["VERDICTS", "SpendGuardrailError", "SHA256_PREFIX", "guardrail_ref", "verify"]

VERDICTS = ("ALLOW", "DENY")
SHA256_PREFIX = "sha256:"
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SpendGuardrailError(ValueError):
    """Raised on an invalid verdict, a malformed reference, or a missing field."""


def _require_ref(name: str, value: str) -> None:
    if not isinstance(value, str) or not _REF_RE.match(value):
        raise SpendGuardrailError(f'{name} must be a "sha256:"-prefixed 64-hex reference')


def guardrail_ref(verdict: str, agent_ref: str, mandate_ref: str, policy_bound_ref: str) -> str:
    """Bind an ALLOW/DENY decision to the agent, the spend authority, and the policy in force."""
    if verdict not in VERDICTS:
        raise SpendGuardrailError(f"verdict must be one of {VERDICTS}, got {verdict!r}")
    _require_ref("agent_ref", agent_ref)
    _require_ref("mandate_ref", mandate_ref)
    _require_ref("policy_bound_ref", policy_bound_ref)
    return SHA256_PREFIX + sha256_jcs(
        {
            "agent_ref": agent_ref,
            "mandate_ref": mandate_ref,
            "policy_bound_ref": policy_bound_ref,
            "verdict": verdict,
        }
    )


def verify(
    guardrail_ref_value: str,
    verdict: str,
    agent_ref: str,
    mandate_ref: str,
    policy_bound_ref: str,
) -> bool:
    """True if (verdict, agent_ref, mandate_ref, policy_bound_ref) recompute to guardrail_ref_value."""
    try:
        return guardrail_ref(verdict, agent_ref, mandate_ref, policy_bound_ref) == guardrail_ref_value
    except SpendGuardrailError:
        return False
