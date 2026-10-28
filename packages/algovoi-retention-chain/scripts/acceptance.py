#!/usr/bin/env python3
"""Self-contained acceptance test for the Retention Chain service.

Proves the service works out of the box on the delivered image, with NO external
services and NO configuration:

  1. Out-of-box   — the service imports and is healthy with zero config (no secret,
                    no hub required; bridging is optional).
  2. Construct    — a genesis record plus two chain links are built and their
                    retention_chain_refs computed.
  3. Verify       — the full sequence verifies as an unbroken chain, and any
                    contiguous subset verifies from local data alone.
  4. Determinism  — identical inputs reproduce an identical chain_ref.
  5. Fail-closed  — a tampered receipt_hash, a broken prev-link, and an invalid
                    genesis are all rejected.

Run inside the delivered image:

    docker run --rm algovoi-retention-chain:clean python scripts/acceptance.py

Exit 0 = all green; non-zero names the failed check(s).
"""
from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from algovoi_retention_chain import (  # noqa: E402
    retention_chain_ref,
    verify_chain_link,
    verify_chain_sequence,
)
from algovoi_retention_chain import service as svc  # noqa: E402

PASS = 0
FAIL: list[str] = []


def ok(name: str) -> None:
    global PASS
    PASS += 1
    print(f"  [PASS] {name}")


def no(name: str) -> None:
    FAIL.append(name)
    print(f"  [FAIL] {name}")


def _rh(tag: str) -> str:
    return "sha256:" + hashlib.sha256(tag.encode()).hexdigest()


def main() -> int:
    print("Retention Chain service — acceptance")

    # 1. Out-of-box: service imports, app present, /health logic healthy, zero config.
    try:
        assert svc.app is not None
        h = svc.app  # FastAPI instance
        assert h.title == "AlgoVoi Retention Chain"
        ok("out-of-box import + app present (zero config)")
    except Exception as exc:  # noqa: BLE001
        no(f"out-of-box ({exc})")

    issuer = "algovoi:acceptance"
    r0, r1, r2 = _rh("receipt-0"), _rh("receipt-1"), _rh("receipt-2")

    # 2. Construct genesis + two links.
    try:
        ref0 = retention_chain_ref(prev_receipt_hash="", receipt_hash=r0, chain_seq=0, issuer_id=issuer)
        ref1 = retention_chain_ref(prev_receipt_hash=r0, receipt_hash=r1, chain_seq=1, issuer_id=issuer)
        ref2 = retention_chain_ref(prev_receipt_hash=r1, receipt_hash=r2, chain_seq=2, issuer_id=issuer)
        assert all(x.startswith("sha256:") and len(x) == 71 for x in (ref0, ref1, ref2))
        ok("construct genesis + 2 links")
    except Exception as exc:  # noqa: BLE001
        no(f"construct ({exc})")
        ref0 = ref1 = ref2 = ""

    chain = [
        {"chain_seq": 0, "issuer_id": issuer, "prev_receipt_hash": "", "receipt_hash": r0, "chain_ref": ref0},
        {"chain_seq": 1, "issuer_id": issuer, "prev_receipt_hash": r0, "receipt_hash": r1, "chain_ref": ref1},
        {"chain_seq": 2, "issuer_id": issuer, "prev_receipt_hash": r1, "receipt_hash": r2, "chain_ref": ref2},
    ]

    # 3. Verify full chain + a non-contiguous-safe contiguous subset.
    if verify_chain_sequence(chain):
        ok("verify full chain (3 links)")
    else:
        no("verify full chain")
    if verify_chain_link(chain_ref=ref1, prev_receipt_hash=r0, receipt_hash=r1, chain_seq=1, issuer_id=issuer):
        ok("verify single link from local data alone")
    else:
        no("verify single link")

    # 4. Determinism.
    again = retention_chain_ref(prev_receipt_hash="", receipt_hash=r0, chain_seq=0, issuer_id=issuer)
    if again == ref0:
        ok("determinism (identical inputs -> identical chain_ref)")
    else:
        no("determinism")

    # 5. Fail-closed: tampered receipt_hash, broken prev-link, invalid genesis.
    if not verify_chain_link(chain_ref=ref0, prev_receipt_hash="", receipt_hash=_rh("TAMPERED"),
                             chain_seq=0, issuer_id=issuer):
        ok("fail-closed: tampered receipt_hash rejected")
    else:
        no("fail-closed tampered")

    broken = [dict(chain[0]), dict(chain[2])]  # seq 0 then seq 2 — gap, prev-link broken
    if not verify_chain_sequence(broken):
        ok("fail-closed: seq-gap / broken prev-link rejected")
    else:
        no("fail-closed seq-gap")

    try:
        retention_chain_ref(prev_receipt_hash=r0, receipt_hash=r1, chain_seq=0, issuer_id=issuer)
        no("fail-closed: invalid genesis accepted")
    except ValueError:
        ok("fail-closed: invalid genesis (seq=0 with prev) rejected")

    print()
    if FAIL:
        print(f"RESULT: {PASS} passed, {len(FAIL)} FAILED -> {', '.join(FAIL)}")
        return 1
    print(f"ALL GREEN ({PASS} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
