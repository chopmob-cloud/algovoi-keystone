"""
AlgoVoi Retention Chain Substrate.

Provides the retention_chain_ref primitive: a self-verifiable audit chain
that links payment receipts without requiring AlgoVoi infrastructure.

Regulatory alignment: MiCA Art. 68(9), DORA Art. 17, AMLR Art. 77.

Preimage schema (JCS-canonical, lexicographic field order):
  {
    "chain_seq":         integer  -- zero-indexed sequence position
    "issuer_id":         string   -- non-empty issuer identifier
    "prev_receipt_hash": string   -- "sha256:<hex>" or "" for genesis
    "receipt_hash":      string   -- "sha256:<hex>" of current receipt JCS bytes
  }

Output: "sha256:" + lowercase_hex(SHA-256(JCS(preimage)))
"""
from __future__ import annotations

import hashlib
import json
from typing import Sequence

import rfc8785


def _jcs(obj: object) -> bytes:
    return rfc8785.dumps(obj)  # type: ignore[no-any-return]


def retention_chain_ref(
    *,
    prev_receipt_hash: str,
    receipt_hash: str,
    chain_seq: int,
    issuer_id: str,
) -> str:
    """Compute the retention_chain_ref for a receipt.

    Args:
        prev_receipt_hash: "sha256:<64-hex>" of the previous receipt, or "" for genesis.
        receipt_hash: "sha256:<64-hex>" of the current receipt's JCS bytes.
        chain_seq: Zero-indexed integer position in the chain.
        issuer_id: Non-empty string identifying the issuing party.

    Returns:
        "sha256:<64-lowercase-hex>" of the JCS-canonical preimage.

    Raises:
        ValueError: on invalid inputs.
    """
    if not isinstance(chain_seq, int) or chain_seq < 0:
        raise ValueError("chain_seq must be a non-negative integer")
    if not issuer_id:
        raise ValueError("issuer_id must be non-empty")
    if chain_seq == 0 and prev_receipt_hash != "":
        raise ValueError("genesis record (chain_seq=0) must have prev_receipt_hash=\"\"")
    if chain_seq > 0 and not _valid_hash(prev_receipt_hash):
        raise ValueError("prev_receipt_hash must be \"sha256:<64-hex>\" for chain_seq > 0")
    if not _valid_hash(receipt_hash):
        raise ValueError("receipt_hash must be \"sha256:<64-hex>\"")

    preimage = {
        "chain_seq": chain_seq,
        "issuer_id": issuer_id,
        "prev_receipt_hash": prev_receipt_hash,
        "receipt_hash": receipt_hash,
    }
    digest = hashlib.sha256(_jcs(preimage)).hexdigest()
    return f"sha256:{digest}"


def verify_chain_link(
    *,
    chain_ref: str,
    prev_receipt_hash: str,
    receipt_hash: str,
    chain_seq: int,
    issuer_id: str,
) -> bool:
    """Verify a single chain link. Returns False on any error or mismatch."""
    try:
        expected = retention_chain_ref(
            prev_receipt_hash=prev_receipt_hash,
            receipt_hash=receipt_hash,
            chain_seq=chain_seq,
            issuer_id=issuer_id,
        )
        return expected == chain_ref
    except Exception:
        return False


def verify_chain_sequence(
    records: Sequence[dict],
    *,
    expected_length: int | None = None,
    expected_head: str | None = None,
    require_genesis: bool = False,
) -> bool:
    """Verify that a sequence of chain records forms a valid unbroken chain.

    Each record must contain: chain_ref, prev_receipt_hash, receipt_hash,
    chain_seq, issuer_id. Records must be ordered by ascending chain_seq, and
    consecutive records in the provided list must be adjacent in the chain (an
    interior hole is rejected).

    SECURITY (2026-08-19): link-verification alone is TRUNCATION-BLIND — a valid prefix, or an interior
    slice (if the first record is not the genesis), verifies clean, so dropping trailing entries or the
    chain's origin is undetectable. To detect truncation you MUST pin the chain against a value the record
    custodian cannot rewrite:

    * ``expected_length`` — the total number of records the chain must contain (from an out-of-band anchor);
    * ``expected_head`` — the ``chain_ref`` of the last (head) record, recorded/published independently;
    * ``require_genesis`` — require the first record to be ``chain_seq == 0`` (the true origin).

    With none of these, the historical subset-verification behaviour is preserved for backward compatibility
    (and an empty ``records`` verifies vacuously); callers that need tamper-evidence against truncation must
    pin at least ``expected_head`` and ``expected_length``.
    """
    if expected_length is not None and len(records) != int(expected_length):
        return False
    if not records:
        # An empty set can only be asserted valid when the caller explicitly anchored a zero-length chain.
        return expected_length == 0 if expected_length is not None else True
    if require_genesis and records[0].get("chain_seq") != 0:
        return False
    for i, rec in enumerate(records):
        if not verify_chain_link(
            chain_ref=rec["chain_ref"],
            prev_receipt_hash=rec["prev_receipt_hash"],
            receipt_hash=rec["receipt_hash"],
            chain_seq=rec["chain_seq"],
            issuer_id=rec["issuer_id"],
        ):
            return False
        if i > 0:
            prev = records[i - 1]
            if rec["chain_seq"] != prev["chain_seq"] + 1:
                return False
            if rec["prev_receipt_hash"] != prev["receipt_hash"]:
                return False
    if expected_head is not None and records[-1].get("chain_ref") != expected_head:
        return False
    return True


def _valid_hash(value: str) -> bool:
    if not value.startswith("sha256:"):
        return False
    hex_part = value[len("sha256:"):]
    return len(hex_part) == 64 and all(c in "0123456789abcdef" for c in hex_part)
