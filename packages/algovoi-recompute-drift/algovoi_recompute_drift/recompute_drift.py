"""Recompute-drift detection for the AlgoVoi action_ref.

A holder of a four-field action record can recompute its ``action_ref`` offline
and detect any drift -- a reordered field (which RFC 8785 JCS absorbs, so it is
*not* drift), a changed field value (drift), or a malformed timestamp form (an
RFC-3339 string instead of an integer millisecond, rejected at validation rather
than silently hashed).

action_ref = hex(SHA-256(JCS(RFC 8785)({agent_id, action_type, scope, timestamp_ms})))
with an integer-millisecond ``timestamp_ms`` (canon ``jcs-rfc8785-v1``). The
recompute is the AlgoVoi substrate's own ``action_ref``; this package adds the
drift predicate and the conformance vectors, additive over the frozen substrate.
"""
from __future__ import annotations

from typing import Any, Mapping

from algovoi_substrate import action_ref

__all__ = ["RecomputeDriftError", "recompute_action_ref", "drift_detected", "assert_no_drift"]

_FIELDS = ("agent_id", "action_type", "scope", "timestamp_ms")


class RecomputeDriftError(ValueError):
    """Raised when a record cannot be canonically recomputed, or drift is asserted absent."""


def _strip(ref: str) -> str:
    return ref[7:] if isinstance(ref, str) and ref.startswith("sha256:") else ref


def recompute_action_ref(record: Mapping[str, Any]) -> str:
    """Canonically recompute the action_ref from the four-field record.

    Raises RecomputeDriftError if a field is missing or malformed (e.g. a
    non-integer ``timestamp_ms``); the substrate validates before hashing, so a
    malformed form is rejected, never minted into a clean-looking identity.
    """
    missing = [f for f in _FIELDS if f not in record]
    if missing:
        raise RecomputeDriftError(f"missing required field(s): {', '.join(missing)}")
    try:
        return action_ref(
            agent_id=record["agent_id"],
            action_type=record["action_type"],
            scope=record["scope"],
            timestamp_ms=record["timestamp_ms"],
        )
    except Exception as exc:  # substrate validation (e.g. ActionRefError) -> drift
        raise RecomputeDriftError(f"record is not canonically recomputable: {exc}") from exc


def drift_detected(claimed_action_ref: str, record: Mapping[str, Any]) -> bool:
    """True if ``record`` does not recompute to ``claimed_action_ref``.

    Drift includes a changed field value and a malformed/unrecomputable record;
    an input whose keys are merely reordered is NOT drift (JCS absorbs key order).
    """
    try:
        return recompute_action_ref(record) != _strip(claimed_action_ref)
    except RecomputeDriftError:
        return True


def assert_no_drift(claimed_action_ref: str, record: Mapping[str, Any]) -> None:
    """Raise RecomputeDriftError if the record has drifted from the claimed action_ref."""
    if drift_detected(claimed_action_ref, record):
        raise RecomputeDriftError("recompute drift detected: record does not match claimed action_ref")
