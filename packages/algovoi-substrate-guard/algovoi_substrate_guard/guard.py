"""algovoi-substrate-guard — deterministic input-bounds gate, run BEFORE canonicalization.

The substrate already fails closed on *malformed* input (the adversarial_isolation set, 8 impls 96/96).
This adds RESOURCE-bound fail-closed: a well-formed but hostile payload (huge, deeply nested, millions of
keys, oversized strings, unsafe numbers) is rejected with a named code before any JCS canonicalization or
hashing happens. It changes no hash and adds no crypto primitive — it is a pure structural validator over
the parsed value, so every bound (depth, count, length) is identical in every language.

Two pieces:
  * ``profile_ref(profile) = "sha256:" + SHA-256(JCS(profile))`` — the limits in force are content-addressed,
    so a record can prove which bounds admitted it (pinnable, same discipline as policy_binding).
  * ``guard(value, profile) -> True | raise GuardError(code)`` — accept or reject, never truncate, never repair.

This is the LITE tier: the open, structural hardening primitive. Runtime defences (rate limiting, replay
windows) live in the commercial verifier layer, never claimed as a substrate property. Additive over the
frozen L1 substrate: no hash change, no new crypto.

Apache-2.0.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from algovoi_substrate import canonicalize_bytes, sha256_jcs

__all__ = ["Profile", "DEFAULT_PROFILE", "GuardError", "profile_ref", "guard"]

SHA256_PREFIX = "sha256:"

# Largest integer representable exactly as an IEEE-754 double, i.e. the JSON safe-integer bound.
_SAFE_INT = 2 ** 53 - 1


class GuardError(ValueError):
    """Raised when a value exceeds a bound. ``code`` is the stable, named reject reason."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Profile:
    """The bounds in force. ``name`` is part of the content address, so a renamed-but-identical-limits
    profile is still distinguishable. ``number_safety`` gates ints to the JSON safe-integer range and
    rejects non-finite floats."""
    name: str = "guard-receipt-v1"
    max_bytes: int = 65536          # UTF-8 length of the canonical (JCS) form
    max_depth: int = 32             # nesting depth (root = 1)
    max_object_keys: int = 256      # keys in any single object
    max_array_length: int = 1024    # items in any single array
    max_string_length: int = 8192   # length of any single string (and object key)
    max_total_nodes: int = 4096     # total values visited (containers + scalars)
    number_safety: bool = True

    def snapshot(self) -> dict:
        """Deterministic, JSON-safe document of the profile — the preimage of ``profile_ref``."""
        return {
            "name": self.name,
            "max_bytes": self.max_bytes,
            "max_depth": self.max_depth,
            "max_object_keys": self.max_object_keys,
            "max_array_length": self.max_array_length,
            "max_string_length": self.max_string_length,
            "max_total_nodes": self.max_total_nodes,
            "number_safety": self.number_safety,
        }


DEFAULT_PROFILE = Profile()


def profile_ref(profile: Profile = DEFAULT_PROFILE) -> str:
    """``"sha256:" + SHA-256(JCS(profile))`` — the pinnable address of the bounds in force.

    Key order does not matter (JCS sorts), so the ref is invariant to how the profile was constructed.
    """
    return SHA256_PREFIX + sha256_jcs(profile.snapshot())


def guard(value, profile: Profile = DEFAULT_PROFILE) -> bool:
    """Validate ``value`` against ``profile``. Return ``True`` or raise :class:`GuardError` (never both,
    never a partial result). Structural bounds are checked in a single pass (cheap, fail-fast); the
    canonical-size bound is checked last, on an already-bounded value.
    """
    nodes = 0

    def walk(v, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > profile.max_total_nodes:
            raise GuardError("REJECT_OVER_NODES")
        if depth > profile.max_depth:
            raise GuardError("REJECT_OVER_DEPTH")
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, int):
            if profile.number_safety and abs(v) > _SAFE_INT:
                raise GuardError("REJECT_UNSAFE_NUMBER")
        elif isinstance(v, float):
            if profile.number_safety and not math.isfinite(v):
                raise GuardError("REJECT_UNSAFE_NUMBER")
        elif isinstance(v, str):
            if len(v) > profile.max_string_length:
                raise GuardError("REJECT_OVER_STRING")
        elif isinstance(v, dict):
            if len(v) > profile.max_object_keys:
                raise GuardError("REJECT_TOO_MANY_KEYS")
            for k, val in v.items():
                if not isinstance(k, str) or len(k) > profile.max_string_length:
                    raise GuardError("REJECT_OVER_STRING")
                walk(val, depth + 1)
        elif isinstance(v, list):
            if len(v) > profile.max_array_length:
                raise GuardError("REJECT_OVER_ARRAY")
            for item in v:
                walk(item, depth + 1)
        else:
            # Not a JSON value (e.g. bytes, set, custom object) — cannot be canonicalised.
            raise GuardError("REJECT_UNSAFE_NUMBER")

    walk(value, 1)

    # Size of the canonical form, now that the structure is bounded (so this cannot blow up).
    if len(canonicalize_bytes(value)) > profile.max_bytes:
        raise GuardError("REJECT_OVER_SIZE")
    return True
