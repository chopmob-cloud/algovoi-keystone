"""Conformance tests for the AlgoVoi Retention Chain Substrate."""
import hashlib
import json
import pytest
import rfc8785

from algovoi_retention_chain import (
    retention_chain_ref,
    retention_chain_ref_linked,
    verify_chain_link,
    verify_chain_sequence,
)

ISSUER = "algovoi:test"

# Fixed receipt hashes (SHA-256 of known byte strings, prefixed)
RECEIPT_0 = "sha256:" + hashlib.sha256(b"receipt_0").hexdigest()
RECEIPT_1 = "sha256:" + hashlib.sha256(b"receipt_1").hexdigest()
RECEIPT_2 = "sha256:" + hashlib.sha256(b"receipt_2").hexdigest()
RECEIPT_3 = "sha256:" + hashlib.sha256(b"receipt_3").hexdigest()


# --- Core algorithm ---

def test_genesis_ref_is_deterministic():
    ref_a = retention_chain_ref(
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id=ISSUER,
    )
    ref_b = retention_chain_ref(
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id=ISSUER,
    )
    assert ref_a == ref_b
    assert ref_a.startswith("sha256:")
    assert len(ref_a) == 71  # "sha256:" + 64 hex chars


def test_genesis_ref_matches_manual_jcs_sha256():
    preimage = {
        "chain_seq": 0,
        "issuer_id": ISSUER,
        "prev_receipt_hash": "",
        "receipt_hash": RECEIPT_0,
    }
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()
    actual = retention_chain_ref(
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id=ISSUER,
    )
    assert actual == expected


def test_link_ref_matches_manual_jcs_sha256():
    genesis_ref = retention_chain_ref(
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id=ISSUER,
    )
    preimage = {
        "chain_seq": 1,
        "issuer_id": ISSUER,
        "prev_receipt_hash": RECEIPT_0,
        "receipt_hash": RECEIPT_1,
    }
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()
    actual = retention_chain_ref(
        prev_receipt_hash=RECEIPT_0,
        receipt_hash=RECEIPT_1,
        chain_seq=1,
        issuer_id=ISSUER,
    )
    assert actual == expected


def test_different_issuers_produce_different_refs():
    ref_a = retention_chain_ref(
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id="issuer-a",
    )
    ref_b = retention_chain_ref(
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id="issuer-b",
    )
    assert ref_a != ref_b


def test_different_seq_produces_different_refs():
    ref_0 = retention_chain_ref(
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id=ISSUER,
    )
    ref_1 = retention_chain_ref(
        prev_receipt_hash=RECEIPT_0,
        receipt_hash=RECEIPT_0,
        chain_seq=1,
        issuer_id=ISSUER,
    )
    assert ref_0 != ref_1


# --- verify_chain_link ---

def test_verify_chain_link_valid_genesis():
    ref = retention_chain_ref(
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id=ISSUER,
    )
    assert verify_chain_link(
        chain_ref=ref,
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id=ISSUER,
    )


def test_verify_chain_link_valid_non_genesis():
    ref = retention_chain_ref(
        prev_receipt_hash=RECEIPT_0,
        receipt_hash=RECEIPT_1,
        chain_seq=1,
        issuer_id=ISSUER,
    )
    assert verify_chain_link(
        chain_ref=ref,
        prev_receipt_hash=RECEIPT_0,
        receipt_hash=RECEIPT_1,
        chain_seq=1,
        issuer_id=ISSUER,
    )


def test_verify_chain_link_wrong_prev():
    ref = retention_chain_ref(
        prev_receipt_hash=RECEIPT_0,
        receipt_hash=RECEIPT_1,
        chain_seq=1,
        issuer_id=ISSUER,
    )
    assert not verify_chain_link(
        chain_ref=ref,
        prev_receipt_hash=RECEIPT_2,  # wrong
        receipt_hash=RECEIPT_1,
        chain_seq=1,
        issuer_id=ISSUER,
    )


def test_verify_chain_link_wrong_seq():
    ref = retention_chain_ref(
        prev_receipt_hash=RECEIPT_0,
        receipt_hash=RECEIPT_1,
        chain_seq=1,
        issuer_id=ISSUER,
    )
    assert not verify_chain_link(
        chain_ref=ref,
        prev_receipt_hash=RECEIPT_0,
        receipt_hash=RECEIPT_1,
        chain_seq=2,  # wrong
        issuer_id=ISSUER,
    )


def test_verify_chain_link_tampered_ref():
    assert not verify_chain_link(
        chain_ref="sha256:" + "a" * 64,
        prev_receipt_hash="",
        receipt_hash=RECEIPT_0,
        chain_seq=0,
        issuer_id=ISSUER,
    )


# --- verify_chain_sequence ---

def _build_chain(receipts: list[str], issuer: str, linked: bool = True) -> list[dict]:
    records = []
    prev_chain_ref = ""
    for i, receipt_hash in enumerate(receipts):
        prev = receipts[i - 1] if i > 0 else ""
        if linked:
            ref = retention_chain_ref_linked(
                prev_receipt_hash=prev,
                receipt_hash=receipt_hash,
                chain_seq=i,
                issuer_id=issuer,
                prev_chain_ref=prev_chain_ref,
            )
        else:
            ref = retention_chain_ref(
                prev_receipt_hash=prev,
                receipt_hash=receipt_hash,
                chain_seq=i,
                issuer_id=issuer,
            )
        records.append({
            "chain_ref": ref,
            "prev_receipt_hash": prev,
            "receipt_hash": receipt_hash,
            "chain_seq": i,
            "issuer_id": issuer,
        })
        if linked:
            prev_chain_ref = ref
    return records


def test_verify_chain_sequence_valid():
    chain = _build_chain([RECEIPT_0, RECEIPT_1, RECEIPT_2, RECEIPT_3], ISSUER)
    assert verify_chain_sequence(chain)


def test_verify_chain_sequence_detects_truncation_with_pins():
    """Security fix 2026-08-19: link-verification alone is truncation-blind. Pinning expected_length +
    expected_head (and require_genesis) detects a dropped tail and a dropped head/interior slice."""
    chain = _build_chain([RECEIPT_0, RECEIPT_1, RECEIPT_2, RECEIPT_3], ISSUER)
    head = chain[-1]["chain_ref"]
    # full chain against its true anchor verifies
    assert verify_chain_sequence(chain, expected_length=4, expected_head=head, require_genesis=True)
    # trailing truncation: drop the last entry -> the prefix still links, but length AND head mismatch
    assert verify_chain_sequence(chain[:3]) is True                      # unpinned: blind (documented)
    assert verify_chain_sequence(chain[:3], expected_length=4) is False  # length pin catches it
    assert verify_chain_sequence(chain[:3], expected_head=head) is False # head pin catches it
    # head/interior slice: dropping the genesis now breaks linkage itself, so it is
    # rejected even with no pins — v1 had to be told about it (require_genesis)
    assert verify_chain_sequence(chain[1:]) is False                      # linkage catches it
    assert verify_chain_sequence(chain[1:], require_genesis=True) is False
    # empty is only valid when a zero-length chain is explicitly anchored
    assert verify_chain_sequence([], expected_length=0) is True
    assert verify_chain_sequence([], expected_length=4) is False


def test_verify_chain_sequence_empty():
    assert verify_chain_sequence([])


def test_verify_chain_sequence_single():
    chain = _build_chain([RECEIPT_0], ISSUER)
    assert verify_chain_sequence(chain)


def test_verify_chain_sequence_tampered_receipt():
    chain = _build_chain([RECEIPT_0, RECEIPT_1, RECEIPT_2], ISSUER)
    chain[1]["receipt_hash"] = RECEIPT_3  # tamper
    assert not verify_chain_sequence(chain)


def test_verify_chain_sequence_broken_link():
    chain = _build_chain([RECEIPT_0, RECEIPT_1, RECEIPT_2], ISSUER)
    chain[2]["prev_receipt_hash"] = RECEIPT_3  # wrong prev
    assert not verify_chain_sequence(chain)


def test_verify_chain_sequence_wrong_seq():
    chain = _build_chain([RECEIPT_0, RECEIPT_1, RECEIPT_2], ISSUER)
    chain[1]["chain_seq"] = 5  # wrong
    assert not verify_chain_sequence(chain)


# --- Input validation ---

def test_negative_chain_seq_raises():
    with pytest.raises(ValueError):
        retention_chain_ref(
            prev_receipt_hash="",
            receipt_hash=RECEIPT_0,
            chain_seq=-1,
            issuer_id=ISSUER,
        )


def test_empty_issuer_id_raises():
    with pytest.raises(ValueError):
        retention_chain_ref(
            prev_receipt_hash="",
            receipt_hash=RECEIPT_0,
            chain_seq=0,
            issuer_id="",
        )


def test_genesis_with_non_empty_prev_raises():
    with pytest.raises(ValueError):
        retention_chain_ref(
            prev_receipt_hash=RECEIPT_0,
            receipt_hash=RECEIPT_1,
            chain_seq=0,
            issuer_id=ISSUER,
        )


def test_non_genesis_with_empty_prev_raises():
    with pytest.raises(ValueError):
        retention_chain_ref(
            prev_receipt_hash="",
            receipt_hash=RECEIPT_1,
            chain_seq=1,
            issuer_id=ISSUER,
        )


def test_invalid_receipt_hash_raises():
    with pytest.raises(ValueError):
        retention_chain_ref(
            prev_receipt_hash="",
            receipt_hash="not-a-hash",
            chain_seq=0,
            issuer_id=ISSUER,
        )


# --- Conformance vector output (run with -s to see) ---

def test_print_conformance_vectors():
    """Prints vectors for cross-impl validation. Not a failure test."""
    chain = _build_chain([RECEIPT_0, RECEIPT_1, RECEIPT_2], ISSUER)
    print("\n\n=== CONFORMANCE VECTORS ===")
    for r in chain:
        print(json.dumps(r, indent=2))
    print("===========================\n")
