"""
RFC 9421 (HTTP Message Signatures) integration for the AlgoVoi Retention Chain.

Requires: pip install algovoi-retention-chain[rfc9421]

verify_signed_chain_link checks two things independently in one call:
  1. The RFC 9421 HTTP signature on the receipt-carrying request.
  2. The retention_chain_ref integrity for that receipt link.

Both must pass for SignedChainLinkResult.valid to be True. The checks
are independent -- a tampered chain ref and a valid signature return
chain_ref_valid=False, signature_valid=True.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union


@dataclass
class SignedChainLinkResult:
    """Result of verify_signed_chain_link."""

    signature_valid: bool = False
    chain_ref_valid: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.signature_valid and self.chain_ref_valid


PublicKey = Union[bytes, str]
"""Ed25519 public key: 32 raw bytes or 64-char hex string."""


def verify_signed_chain_link(
    *,
    method: str,
    authority: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    public_key: PublicKey,
    chain_ref: str,
    prev_receipt_hash: str,
    receipt_hash: str,
    chain_seq: int,
    issuer_id: str,
    scheme: str = "https",
    require_content_digest: bool = True,
    mode: str = "rfc9421",
) -> SignedChainLinkResult:
    """Verify an RFC 9421-signed HTTP request carrying a retention chain link.

    Args:
        method, authority, path, headers, body: HTTP request components.
        public_key: Ed25519 public key (64-char hex string or 32 raw bytes).
        chain_ref: The ``retention_chain_ref`` value claimed by the receipt.
        prev_receipt_hash: ``"sha256:<64-hex>"`` of the previous receipt, or
            ``""`` for a genesis link (chain_seq == 0).
        receipt_hash: ``"sha256:<64-hex>"`` of the current receipt's JCS bytes.
        chain_seq: Zero-indexed integer position in the chain.
        issuer_id: Non-empty string identifying the issuing party.
        scheme: URL scheme. Defaults to ``"https"``.
        require_content_digest: If True, the request must carry a valid
            Content-Digest header.  Set to False only for bodyless requests.
        mode: Signing-base construction mode.  ``"rfc9421"`` (default) is RFC
            9421 §2.5 compliant.  ``"algovoi-v0"`` preserves the legacy shape
            used by the ``rfc9421_proxy_chain_v0`` conformance fixture set.

    Returns:
        :class:`SignedChainLinkResult` with ``signature_valid``,
        ``chain_ref_valid``, ``valid``, and ``errors``.

    Raises:
        ImportError: if ``algovoi-rfc9421-verifier`` is not installed.
    """
    try:
        from algovoi_rfc9421_verifier import verify_request
    except ImportError as exc:
        raise ImportError(
            "algovoi-rfc9421-verifier is required for RFC 9421 verification. "
            "Install with: pip install algovoi-retention-chain[rfc9421]"
        ) from exc

    from algovoi_retention_chain.chain import verify_chain_link

    result = SignedChainLinkResult()

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

    result.chain_ref_valid = verify_chain_link(
        chain_ref=chain_ref,
        prev_receipt_hash=prev_receipt_hash,
        receipt_hash=receipt_hash,
        chain_seq=chain_seq,
        issuer_id=issuer_id,
    )
    if not result.chain_ref_valid:
        result.errors.append("retention_chain_ref does not match")

    return result
