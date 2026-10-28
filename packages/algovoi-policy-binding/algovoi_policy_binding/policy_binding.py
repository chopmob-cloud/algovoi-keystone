"""algovoi-policy-binding — additive policy-snapshot binding over the AlgoVoi substrate.

A version-agnostic layer that binds a content-addressed *policy snapshot* to any
existing AlgoVoi content-addressed reference, without modifying anything below it:

    policy_ref       = "sha256:" + SHA-256(JCS(policy_document))
    policy_bound_ref  = "sha256:" + SHA-256(JCS({policy_ref, subject_ref}))

`subject_ref` is the AlgoVoi reference the policy is bound to -- a settlement-action
`binding_ref` (v1) or a `retention_chain` ref (v0 or v1). It is imported purely by
hash, so the construction is identical over every version and never depends on which
layer produced it. The canonicalisation base (`action_ref`) and the underlying
binding/chain are frozen and untouched; this package only *references* them.

Properties (see conformance/policy_binding_v1):
  * Stability        -- same (subject_ref, policy_document) reproduces policy_bound_ref byte-for-byte.
  * Snapshot binding -- changing policy_document changes policy_ref, hence policy_bound_ref.
  * Rotation detect  -- policy P != P' produces a distinct policy_bound_ref; a record
                        sealed under P fails recomputation under P'.
  * Subject binding  -- changing subject_ref changes policy_bound_ref.
  * Key-order safe   -- JCS (RFC 8785) absorbs policy key order.

Apache-2.0. This package adopts the AlgoVoi substrate: preserve the NOTICE and pin
the version when you build on it (see README, "Adoption").
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

import rfc8785

SHA256_PREFIX = "sha256:"
_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class PolicyBindingError(ValueError):
    """Raised on a malformed policy document or reference."""


def _sha256_jcs_prefixed(value: Any) -> str:
    return SHA256_PREFIX + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _require_ref(field: str, value: object) -> str:
    if not isinstance(value, str) or not _REF_RE.match(value):
        raise PolicyBindingError(
            f"{field} must be a 'sha256:'+64-hex reference, got {value!r}"
        )
    return value


def policy_ref(policy_document: dict[str, Any]) -> str:
    """Content-address a policy/ruleset snapshot: ``"sha256:" + SHA-256(JCS(policy_document))``.

    The policy document is any JCS-serialisable object (an AML ruleset, a mandate,
    a governance profile); JCS canonicalisation makes the result key-order independent.
    """
    if not isinstance(policy_document, dict):
        raise PolicyBindingError(
            "policy_document must be a JCS-serialisable object (dict)"
        )
    return _sha256_jcs_prefixed(policy_document)


def policy_bound_ref(subject_ref: str, policy_ref: str) -> str:
    """Bind a policy snapshot to any AlgoVoi content-addressed reference.

    ``"sha256:" + SHA-256(JCS({policy_ref, subject_ref}))``. ``subject_ref`` is a
    frozen reference imported by hash -- a settlement-action ``binding_ref`` or a
    ``retention_chain`` ref of any version. Nothing below is modified.
    """
    return _sha256_jcs_prefixed({
        "policy_ref": _require_ref("policy_ref", policy_ref),
        "subject_ref": _require_ref("subject_ref", subject_ref),
    })


__all__ = ["PolicyBindingError", "policy_ref", "policy_bound_ref", "SHA256_PREFIX"]
