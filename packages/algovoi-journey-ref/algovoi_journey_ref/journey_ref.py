"""Content-addressed journey references for the AlgoVoi substrate.

A journey_ref binds a whole multi-agent task into one reference: every hop's
execution plus the delegations between them, with a closed outcome.

    journey_ref = "sha256:" + SHA-256(JCS(RFC 8785)({
        delegations, hops, journey_outcome }))

``hops`` and ``delegations`` are ordered lists of "sha256:"-prefixed refs.
Construction only; the end-to-end PROOF (continuity, scope never widened, nothing
under a revoked grant, no hop omitted) is a separate AlgoVoi component.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from algovoi_substrate import sha256_jcs

__all__ = ["JourneyRefError", "SHA256_PREFIX", "OUTCOMES", "journey_ref", "tamper_detected"]

SHA256_PREFIX = "sha256:"
OUTCOMES = ("COMPLETE", "PARTIAL", "ABORTED")
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class JourneyRefError(ValueError):
    """Raised when a journey envelope is malformed."""


def _reflist(val: Any, name: str, *, allow_empty: bool) -> list:
    if not isinstance(val, (list, tuple)):
        raise JourneyRefError(f"{name} must be a list of refs")
    if not allow_empty and not val:
        raise JourneyRefError(f"{name} must be non-empty")
    out = []
    for r in val:
        if not isinstance(r, str) or not _REF_RE.match(r):
            raise JourneyRefError(f'{name} entries must be "sha256:"-prefixed 64-hex refs')
        out.append(r)
    return out


def journey_ref(env: Mapping[str, Any]) -> str:
    """Compute the content-addressed journey_ref for a journey envelope."""
    hops = _reflist(env.get("hops"), "hops", allow_empty=False)
    delegations = _reflist(env.get("delegations", []), "delegations", allow_empty=True)
    outcome = env.get("journey_outcome")
    if outcome not in OUTCOMES:
        raise JourneyRefError(f"journey_outcome must be one of {OUTCOMES}")
    return SHA256_PREFIX + sha256_jcs({"delegations": delegations, "hops": hops, "journey_outcome": outcome})


def tamper_detected(claimed_ref: str, env: Mapping[str, Any]) -> bool:
    """True if ``env`` does not recompute to ``claimed_ref`` (tamper / malformed)."""
    try:
        return journey_ref(env) != claimed_ref
    except JourneyRefError:
        return True
