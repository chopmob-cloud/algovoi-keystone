"""
COMMERCIAL / LOCAL-ONLY -- not part of the public algovoi-retention-chain
distribution. Excluded from the published wheel and sdist (see pyproject
[tool.hatch.build.targets.*] exclude). Deployed only with the commercial
retention-chain product on AlgoVoi VMs.

RFC 9421 (HTTP Message Signatures) verification for the settlement-action
binding. This is the signed (v1) companion to the public JCS (v0) binding in
algovoi-substrate; the open reference stays public, the signed core stays
commercial.

verify_signed_binding checks two things independently in one call:
  1. The RFC 9421 HTTP signature on the binding-carrying request.
  2. That the claimed binding_ref equals the binding recomputed from the four
     component references via algovoi_substrate.settlement_action_binding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

PublicKey = Union[bytes, str]
"""Ed25519 public key: 32 raw bytes or 64-char hex string."""


@dataclass
class SignedBindingResult:
    """Result of verify_signed_binding."""

    signature_valid: bool = False
    binding_ref_valid: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.signature_valid and self.binding_ref_valid


def verify_signed_binding(
    *,
    method: str,
    authority: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    public_key: PublicKey,
    action_ref: str,
    transition_hash: str,
    settlement_ref: str,
    retention_chain_ref: str,
    claimed_binding_ref: str,
    scheme: str = "https",
    require_content_digest: bool = True,
    mode: str = "rfc9421",
) -> SignedBindingResult:
    """Verify an RFC 9421-signed HTTP request carrying a settlement-action binding.

    Checks two things independently in one call:
      1. The RFC 9421 HTTP signature on the binding-carrying request.
      2. That ``claimed_binding_ref`` equals the binding recomputed from the four
         component references via ``algovoi_substrate.settlement_action_binding``.

    Both must pass for :attr:`SignedBindingResult.valid`. The checks are
    independent -- a corrupted signature with a correct binding returns
    signature_valid=False, binding_ref_valid=True; a valid signature over a body
    whose claimed binding is wrong returns signature_valid=True,
    binding_ref_valid=False.

    Raises:
        ImportError: if ``algovoi-rfc9421-verifier`` or ``algovoi-substrate`` is missing.
    """
    try:
        from algovoi_rfc9421_verifier import verify_request
    except ImportError as exc:
        raise ImportError(
            "algovoi-rfc9421-verifier is required for RFC 9421 verification. "
            "Install with: pip install algovoi-retention-chain[rfc9421]"
        ) from exc
    try:
        from algovoi_substrate import settlement_action_binding
    except ImportError as exc:
        raise ImportError(
            "algovoi-substrate>=0.4.0 is required for binding recomputation."
        ) from exc

    result = SignedBindingResult()

    sig_result = verify_request(
        method=method,
        authority=authority,
        path=path,
        headers=headers,
        body=body,
        public_key=public_key,
        scheme=scheme,
        require_content_digest=require_content_digest,
        mode=mode,
    )
    result.signature_valid = sig_result.valid
    if not sig_result.valid:
        result.errors.extend(sig_result.errors)

    recomputed = settlement_action_binding(
        action_ref, transition_hash, settlement_ref, retention_chain_ref)
    result.binding_ref_valid = (recomputed == claimed_binding_ref)
    if not result.binding_ref_valid:
        result.errors.append(
            f"binding_ref does not match: claimed {claimed_binding_ref}, recomputed {recomputed}")

    return result
