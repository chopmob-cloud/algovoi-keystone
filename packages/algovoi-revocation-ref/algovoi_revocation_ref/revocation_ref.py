"""Content-addressed revocation references for the AlgoVoi substrate.

A grantor revokes a delegation (or other authority) before it expires. The
``revocation_ref`` is the content hash of the revocation envelope, so any tamper
(changing the target, the time, the reason or the revoker) changes the ref and is
detectable offline. Revocations chain via ``prev_revocation_ref``.

    revocation_ref = "sha256:" + SHA-256(JCS(RFC 8785)({
        prev_revocation_ref, reason, revoked_at_ms, revoked_ref, revoker_id }))

with an integer-millisecond ``revoked_at_ms``. Construction only; the revocation
cascade PROOF (an action at or after revoked_at_ms acted under revoked authority)
is a separate AlgoVoi component.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from algovoi_substrate import sha256_jcs

__all__ = ["RevocationRefError", "SHA256_PREFIX", "REASONS", "revocation_ref",
           "tamper_detected", "verify_chain"]

SHA256_PREFIX = "sha256:"
REASONS = ("COMPROMISE", "SUPERSEDED", "POLICY", "EXPIRY", "MANUAL")
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RevocationRefError(ValueError):
    """Raised when a revocation envelope is malformed or a chain link does not match."""


def _normalise(env: Mapping[str, Any]) -> dict:
    out: dict[str, Any] = {}
    rid = env.get("revoker_id")
    if not isinstance(rid, str) or not rid:
        raise RevocationRefError("revoker_id must be a non-empty string")
    out["revoker_id"] = rid
    rr = env.get("revoked_ref")
    if not isinstance(rr, str) or not _REF_RE.match(rr):
        raise RevocationRefError('revoked_ref must be a "sha256:"-prefixed 64-hex ref')
    out["revoked_ref"] = rr
    reason = env.get("reason")
    if reason not in REASONS:
        raise RevocationRefError(f"reason must be one of {REASONS}")
    out["reason"] = reason
    ra = env.get("revoked_at_ms")
    if isinstance(ra, bool) or not isinstance(ra, int) or ra < 0:
        raise RevocationRefError("revoked_at_ms must be a non-negative integer (integer-millisecond)")
    out["revoked_at_ms"] = ra
    prev = env.get("prev_revocation_ref", "")
    if prev != "" and not _REF_RE.match(prev):
        raise RevocationRefError('prev_revocation_ref must be "" or a "sha256:"-prefixed 64-hex ref')
    out["prev_revocation_ref"] = prev
    return out


def revocation_ref(env: Mapping[str, Any]) -> str:
    """Compute the content-addressed revocation_ref for a revocation envelope."""
    n = _normalise(env)
    return SHA256_PREFIX + sha256_jcs({
        "prev_revocation_ref": n["prev_revocation_ref"], "reason": n["reason"],
        "revoked_at_ms": n["revoked_at_ms"], "revoked_ref": n["revoked_ref"],
        "revoker_id": n["revoker_id"],
    })


def tamper_detected(claimed_ref: str, env: Mapping[str, Any]) -> bool:
    """True if ``env`` does not recompute to ``claimed_ref`` (tamper / malformed)."""
    try:
        return revocation_ref(env) != claimed_ref
    except RevocationRefError:
        return True


def verify_chain(envelopes: Sequence[Mapping[str, Any]]) -> list[str]:
    """Compute the revocation_ref of each link and verify chain integrity via prev_revocation_ref."""
    refs: list[str] = []
    prev = ""
    for i, env in enumerate(envelopes):
        if env.get("prev_revocation_ref", "") != prev:
            raise RevocationRefError(f"chain break at link {i}: prev_revocation_ref does not match the prior link")
        r = revocation_ref(env)
        refs.append(r)
        prev = r
    return refs
