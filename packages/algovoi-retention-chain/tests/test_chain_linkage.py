"""The chain head pin must commit to every earlier link, not just the head record.

retention_chain_ref hashed {chain_seq, issuer_id, prev_receipt_hash, receipt_hash}
and never the previous record's own chain_ref. Adjacency was checked against
prev_receipt_hash, a *declared* value, so interior records could be rewritten —
and re-signed consistently — while the pinned head stayed byte-identical.
"""
import pytest

from algovoi_retention_chain.chain import (
    retention_chain_ref,
    retention_chain_ref_linked,
    verify_chain_sequence,
)


def build(n=5, issuer="issuer-A", linked=True):
    recs, prev_receipt, prev_chain = [], "", ""
    for i in range(n):
        receipt = f"sha256:{i:064x}"
        ref = retention_chain_ref_linked(
            prev_receipt_hash=prev_receipt, receipt_hash=receipt,
            chain_seq=i, issuer_id=issuer, prev_chain_ref=prev_chain,
        ) if linked else retention_chain_ref(
            prev_receipt_hash=prev_receipt, receipt_hash=receipt,
            chain_seq=i, issuer_id=issuer)
        recs.append({"chain_seq": i, "issuer_id": issuer, "prev_receipt_hash": prev_receipt,
                     "receipt_hash": receipt, "chain_ref": ref})
        prev_receipt, prev_chain = receipt, ref
    return recs


def test_untampered_linked_chain_verifies():
    recs = build()
    assert verify_chain_sequence(recs, expected_length=5, expected_head=recs[-1]["chain_ref"])


def test_rewriting_an_interior_issuer_breaks_the_pinned_head():
    recs = build()
    head = recs[-1]["chain_ref"]
    tampered = [dict(r) for r in recs]
    for i in range(len(recs) - 1):
        tampered[i]["issuer_id"] = "attacker-B"
        # re-derive each link consistently, including its link to the previous one
        tampered[i]["chain_ref"] = retention_chain_ref_linked(
            prev_receipt_hash=tampered[i]["prev_receipt_hash"],
            receipt_hash=tampered[i]["receipt_hash"],
            chain_seq=tampered[i]["chain_seq"], issuer_id="attacker-B",
            prev_chain_ref=tampered[i - 1]["chain_ref"] if i else "",
        )
    assert verify_chain_sequence(tampered, expected_length=5, expected_head=head) is False


def test_rewriting_the_first_record_alone_breaks_the_head():
    recs = build()
    head = recs[-1]["chain_ref"]
    tampered = [dict(r) for r in recs]
    tampered[0]["receipt_hash"] = f"sha256:{'f' * 64}"
    tampered[0]["chain_ref"] = retention_chain_ref_linked(
        prev_receipt_hash="", receipt_hash=tampered[0]["receipt_hash"],
        chain_seq=0, issuer_id=tampered[0]["issuer_id"], prev_chain_ref="")
    assert verify_chain_sequence(tampered, expected_length=5, expected_head=head) is False


def test_truncation_is_still_detected():
    recs = build()
    head = recs[-1]["chain_ref"]
    assert verify_chain_sequence(recs[:3], expected_length=5, expected_head=head) is False


def test_unlinked_legacy_chain_is_rejected_by_default():
    recs = build(linked=False)
    assert verify_chain_sequence(recs, expected_length=5) is False


def test_unlinked_legacy_chain_can_be_accepted_only_by_explicit_opt_out():
    recs = build(linked=False)
    assert verify_chain_sequence(recs, expected_length=5, allow_legacy_v1=True) is True


def test_linked_and_unlinked_hashes_differ_for_the_same_record():
    common = dict(prev_receipt_hash="", receipt_hash=f"sha256:{'a' * 64}",
                  chain_seq=0, issuer_id="issuer-A")
    assert retention_chain_ref(**common) != retention_chain_ref_linked(**common, prev_chain_ref="")


def test_prev_chain_ref_must_be_a_hash_when_supplied():
    with pytest.raises(ValueError):
        retention_chain_ref_linked(prev_receipt_hash="", receipt_hash=f"sha256:{'a' * 64}",
                                   chain_seq=1, issuer_id="issuer-A", prev_chain_ref="nope")
