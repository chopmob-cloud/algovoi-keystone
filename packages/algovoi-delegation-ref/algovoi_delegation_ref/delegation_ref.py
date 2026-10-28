"""Content-addressed delegation references for the AlgoVoi substrate.

An agent A delegates authority to agent B for a scope and a validity window. The
``delegation_ref`` is the content hash of that delegation envelope, so any tamper
-- widening the scope, extending the expiry, swapping the delegate -- changes the
ref and is detectable offline. Delegations chain (A->B->C) via
``prev_delegation_ref``, giving a tamper-evident delegation chain.

This is the inverse of an *opaque* delegation token (an arbitrary label chosen by
the authority, which does not change when the delegation's content is altered).

    delegation_ref = "sha256:" + SHA-256(JCS(RFC 8785)({
        delegate_id, delegator_id, not_after_ms, not_before_ms,
        prev_delegation_ref, scope }))

with integer-millisecond validity bounds. Additive over the frozen substrate; the
canonical hash is the substrate's own ``sha256_jcs``.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from algovoi_substrate import sha256_jcs

__all__ = [
    "DelegationRefError",
    "SHA256_PREFIX",
    "delegation_ref",
    "tamper_detected",
    "verify_chain",
]

SHA256_PREFIX = "sha256:"
_FIELDS = ("delegate_id", "delegator_id", "not_after_ms", "not_before_ms",
           "prev_delegation_ref", "scope")
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class DelegationRefError(ValueError):
    """Raised when a delegation envelope is malformed or a chain link does not match."""


def _normalise(envelope: Mapping[str, Any]) -> dict:
    out: dict[str, Any] = {}
    for name in ("delegator_id", "delegate_id", "scope"):
        val = envelope.get(name)
        if not isinstance(val, str) or not val:
            raise DelegationRefError(f"{name} must be a non-empty string")
        out[name] = val
    for name in ("not_before_ms", "not_after_ms"):
        val = envelope.get(name)
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            raise DelegationRefError(f"{name} must be a non-negative integer (integer-millisecond)")
        out[name] = val
    if out["not_after_ms"] <= out["not_before_ms"]:
        raise DelegationRefError("not_after_ms must be greater than not_before_ms")
    prev = envelope.get("prev_delegation_ref", "")
    if prev != "" and not _REF_RE.match(prev):
        raise DelegationRefError('prev_delegation_ref must be "" or a "sha256:"-prefixed 64-hex ref')
    out["prev_delegation_ref"] = prev
    return out


def delegation_ref(envelope: Mapping[str, Any]) -> str:
    """Compute the content-addressed delegation_ref for a delegation envelope."""
    n = _normalise(envelope)
    return SHA256_PREFIX + sha256_jcs({
        "delegate_id": n["delegate_id"],
        "delegator_id": n["delegator_id"],
        "not_after_ms": n["not_after_ms"],
        "not_before_ms": n["not_before_ms"],
        "prev_delegation_ref": n["prev_delegation_ref"],
        "scope": n["scope"],
    })


def tamper_detected(claimed_ref: str, envelope: Mapping[str, Any]) -> bool:
    """True if ``envelope`` does not recompute to ``claimed_ref`` (tamper / malformed)."""
    try:
        return delegation_ref(envelope) != claimed_ref
    except DelegationRefError:
        return True


def verify_chain(envelopes: Sequence[Mapping[str, Any]]) -> list[str]:
    """Compute the delegation_ref of each link and verify chain integrity.

    The first link must have ``prev_delegation_ref == ""``; every subsequent link's
    ``prev_delegation_ref`` must equal the prior link's computed ref. Returns the
    list of refs; raises DelegationRefError on a broken or forged link.
    """
    refs: list[str] = []
    prev = ""
    for i, env in enumerate(envelopes):
        if env.get("prev_delegation_ref", "") != prev:
            raise DelegationRefError(
                f"chain break at link {i}: prev_delegation_ref does not match the prior link")
        ref = delegation_ref(env)
        refs.append(ref)
        prev = ref
    return refs
