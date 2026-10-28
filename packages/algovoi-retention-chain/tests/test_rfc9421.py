"""Tests for RFC 9421 integration (algovoi_retention_chain.rfc9421)."""
import hashlib
import json
import pathlib
import pytest

import rfc8785

from algovoi_retention_chain.rfc9421 import verify_signed_chain_link, SignedChainLinkResult
from algovoi_retention_chain.chain import retention_chain_ref

pytest.importorskip(
    "algovoi_rfc9421_signer",
    reason="optional RFC 9421 signer not installed; signing-vector tests skipped",
)

VECTORS_FILE = pathlib.Path(__file__).parent.parent.parent / "vectors" / "retention-chain-rfc9421-v1.json"

SEED   = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
PUBKEY = "700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41"
KEYID  = "did:web:api.algovoi.co.uk"
ISSUER = "algovoi:test"
CREATED = 1750000000


def _sign_receipt(receipt_obj: dict, private_key: str = SEED) -> tuple[bytes, dict]:
    from algovoi_rfc9421_signer import sign_request
    body = rfc8785.dumps(receipt_obj)
    signed = sign_request(
        method="POST",
        authority="api.algovoi.co.uk",
        path="/v1/receipts",
        body=body,
        private_key=private_key,
        keyid=KEYID,
        created=CREATED,
        label="sig",
    )
    headers = {
        "content-digest": signed.content_digest,
        "signature-input": signed.signature_input,
        "signature": signed.signature,
    }
    return body, headers


def _receipt_hash(receipt_obj: dict) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(receipt_obj)).hexdigest()


# --- Canonical vector file ---

def test_vectors_file_exists():
    assert VECTORS_FILE.exists(), f"Missing vector file: {VECTORS_FILE}"


def test_canonical_vectors_all_pass():
    data = json.loads(VECTORS_FILE.read_text())
    pk = data["keypair"]["public_key_hex"]
    for v in data["vectors"]:
        body = bytes.fromhex(v["http"]["body_hex"])
        result = verify_signed_chain_link(
            method=v["http"]["method"],
            authority=v["http"]["authority"],
            path=v["http"]["path"],
            headers=v["http"]["headers"],
            body=body,
            public_key=pk,
            chain_ref=v["retention_chain_ref"],
            prev_receipt_hash=v["prev_receipt_hash"],
            receipt_hash=v["receipt_hash"],
            chain_seq=v["chain_seq"],
            issuer_id=v["issuer_id"],
        )
        assert result.signature_valid is v["expect"]["signature_valid"], (
            f"[{v['description']}] signature_valid: {result.errors}"
        )
        assert result.chain_ref_valid is v["expect"]["chain_ref_valid"], (
            f"[{v['description']}] chain_ref_valid"
        )
        assert result.valid is v["expect"]["valid"], (
            f"[{v['description']}] valid"
        )


# --- Property tests ---

def test_result_valid_requires_both():
    r = SignedChainLinkResult(signature_valid=True, chain_ref_valid=False)
    assert not r.valid
    r2 = SignedChainLinkResult(signature_valid=False, chain_ref_valid=True)
    assert not r2.valid
    r3 = SignedChainLinkResult(signature_valid=True, chain_ref_valid=True)
    assert r3.valid


def test_genesis_signed_receipt_passes():
    receipt = {"payment_id": "pay_001", "amount": 100, "currency": "USD"}
    r_hash = _receipt_hash(receipt)
    chain_ref = retention_chain_ref(
        prev_receipt_hash="", receipt_hash=r_hash, chain_seq=0, issuer_id=ISSUER
    )
    body, headers = _sign_receipt(receipt)
    result = verify_signed_chain_link(
        method="POST", authority="api.algovoi.co.uk", path="/v1/receipts",
        headers=headers, body=body, public_key=PUBKEY,
        chain_ref=chain_ref, prev_receipt_hash="", receipt_hash=r_hash,
        chain_seq=0, issuer_id=ISSUER,
    )
    assert result.valid
    assert result.signature_valid
    assert result.chain_ref_valid


def test_tampered_body_fails_signature():
    receipt = {"payment_id": "pay_001", "amount": 100, "currency": "USD"}
    r_hash = _receipt_hash(receipt)
    chain_ref = retention_chain_ref(
        prev_receipt_hash="", receipt_hash=r_hash, chain_seq=0, issuer_id=ISSUER
    )
    body, headers = _sign_receipt(receipt)
    tampered_body = body + b" "
    result = verify_signed_chain_link(
        method="POST", authority="api.algovoi.co.uk", path="/v1/receipts",
        headers=headers, body=tampered_body, public_key=PUBKEY,
        chain_ref=chain_ref, prev_receipt_hash="", receipt_hash=r_hash,
        chain_seq=0, issuer_id=ISSUER,
    )
    assert not result.valid
    assert not result.signature_valid
    assert result.errors


def test_wrong_chain_ref_fails_chain_only():
    receipt = {"payment_id": "pay_001", "amount": 100, "currency": "USD"}
    r_hash = _receipt_hash(receipt)
    body, headers = _sign_receipt(receipt)
    result = verify_signed_chain_link(
        method="POST", authority="api.algovoi.co.uk", path="/v1/receipts",
        headers=headers, body=body, public_key=PUBKEY,
        chain_ref="sha256:" + "a" * 64,
        prev_receipt_hash="", receipt_hash=r_hash,
        chain_seq=0, issuer_id=ISSUER,
    )
    assert not result.valid
    assert result.signature_valid
    assert not result.chain_ref_valid
    assert any("retention_chain_ref" in e for e in result.errors)


def test_wrong_public_key_fails_signature_only():
    receipt = {"payment_id": "pay_001", "amount": 100, "currency": "USD"}
    r_hash = _receipt_hash(receipt)
    chain_ref = retention_chain_ref(
        prev_receipt_hash="", receipt_hash=r_hash, chain_seq=0, issuer_id=ISSUER
    )
    body, headers = _sign_receipt(receipt)
    wrong_pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    result = verify_signed_chain_link(
        method="POST", authority="api.algovoi.co.uk", path="/v1/receipts",
        headers=headers, body=body, public_key=wrong_pk,
        chain_ref=chain_ref, prev_receipt_hash="", receipt_hash=r_hash,
        chain_seq=0, issuer_id=ISSUER,
    )
    assert not result.valid
    assert not result.signature_valid
    assert result.chain_ref_valid


def test_chain_of_three_receipts():
    receipts = [
        {"payment_id": "pay_001", "amount": 100, "currency": "USD"},
        {"payment_id": "pay_002", "amount": 200, "currency": "USD"},
        {"payment_id": "pay_003", "amount": 300, "currency": "USD"},
    ]
    hashes = [_receipt_hash(r) for r in receipts]
    prev = ""
    for i, (r_obj, r_hash) in enumerate(zip(receipts, hashes)):
        chain_ref = retention_chain_ref(
            prev_receipt_hash=prev, receipt_hash=r_hash,
            chain_seq=i, issuer_id=ISSUER,
        )
        body, headers = _sign_receipt(r_obj)
        result = verify_signed_chain_link(
            method="POST", authority="api.algovoi.co.uk", path="/v1/receipts",
            headers=headers, body=body, public_key=PUBKEY,
            chain_ref=chain_ref, prev_receipt_hash=prev, receipt_hash=r_hash,
            chain_seq=i, issuer_id=ISSUER,
        )
        assert result.valid, f"link {i} failed: {result.errors}"
        prev = r_hash
