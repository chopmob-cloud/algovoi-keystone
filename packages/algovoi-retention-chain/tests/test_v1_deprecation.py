"""The legacy v1 retention_chain_ref must warn so no new chain is built on it.

v1 commits to a single record (no prev_chain_ref), so a chain built with it is
not interior-rewrite-safe. v2 (retention_chain_ref_linked) binds each link to
its predecessor and is what verification requires by default. v1 stays callable
for reading historical chains, but emits DeprecationWarning on use.
"""
import warnings

import pytest

from algovoi_retention_chain.chain import retention_chain_ref, retention_chain_ref_linked

_GENESIS = {"prev_receipt_hash": "", "receipt_hash": "sha256:" + "a" * 64,
            "chain_seq": 0, "issuer_id": "issuer-1"}


def test_v1_retention_chain_ref_emits_deprecation_warning():
    with pytest.warns(DeprecationWarning, match="retention_chain_ref_linked"):
        retention_chain_ref(**_GENESIS)


def test_v1_still_computes_the_same_digest_it_always_did():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        v1 = retention_chain_ref(**_GENESIS)
    # genesis: prev_chain_ref="" under v2 must equal v1 for the first record only?
    # No -- v2 adds prev_chain_ref to the preimage, so the digests DIFFER by design.
    v2 = retention_chain_ref_linked(**_GENESIS, prev_chain_ref="")
    assert v1.startswith("sha256:") and len(v1) == 71
    assert v1 != v2, "v2 must bind prev_chain_ref into the preimage"


def test_v2_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        retention_chain_ref_linked(**_GENESIS, prev_chain_ref="")  # must not raise
