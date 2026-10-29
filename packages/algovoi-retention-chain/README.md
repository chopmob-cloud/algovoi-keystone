# algovoi-retention-chain

Self-verifiable audit chain for payment receipts. Apache-2.0.

Each receipt carries a `retention_chain_ref` computed as:

```
retention_chain_ref = SHA-256(JCS({chain_seq, issuer_id, prev_receipt_hash, receipt_hash}))
```

Any party holding a receipt set can verify chain integrity by recomputing the reference
from locally held data alone. No AlgoVoi infrastructure, registry lookup, or network
access required.

Satisfies transaction-recording and audit-trail obligations under MiCA Art. 68(9),
DORA Art. 17, and AMLR Art. 77. Normative spec:
[draft-hopley-x402-retention-chain](https://datatracker.ietf.org/doc/draft-hopley-x402-retention-chain/)
(IETF Independent Submission — latest revision).

## Install

```
pip install algovoi-retention-chain
```

## Usage

```python
from algovoi_retention_chain import retention_chain_ref, verify_chain_sequence

# Compute a chain ref for an authorized charge
ref = retention_chain_ref(
    prev_receipt_hash="",                          # "" for the genesis (first) charge
    receipt_hash="sha256:<64-hex>",                # SHA-256 of your receipt payload
    chain_seq=0,
    issuer_id="mandate:acct-123",                  # scope per mandate / account
)
# ref = "sha256:<64-hex>" — embed in the receipt; any holder can recompute it

# Verify a full sequence offline
chain = [
    {"chain_seq": 0, "issuer_id": "mandate:acct-123",
     "prev_receipt_hash": "", "receipt_hash": "sha256:...", "chain_ref": "sha256:..."},
    {"chain_seq": 1, ...},
]
assert verify_chain_sequence(chain)
```

## Conformance vectors

Canonical test vectors (v0 and v1) are published at
[`chopmob-cloud/algovoi-jcs-conformance-vectors`](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors/tree/main/vectors/retention_chain_v1),
verified byte-for-byte across Python, TypeScript, Go, Rust, Ruby, C#, Java, and Kotlin (2026-06-17).

The v1 set covers three invariant classes:
- **Part A** — 6-link extended chain (seq 0–5, single issuer)
- **Part B** — multi-issuer isolation (same receipt, different `issuer_id` → different `chain_ref`)
- **Part C** — seq-gap adversarial pair (correct vs tampered `prev_receipt_hash` → different `chain_ref`)

Use these in your test suite to prove interoperability. If you embed at least one canonical
hash in your conformance tests, you qualify for the Adopters programme below.

## Adopters — free mandate auditor key

If you build on `algovoi-retention-chain` and meet the criteria below, you qualify
for a free **v0 licence key** for `algovoi-mandate-auditor`
— AlgoVoi's production-grade MiCA/DORA compliance audit service for payment mandate charge chains.

**Qualification criteria:**

1. `algovoi-retention-chain` declared as a dependency, pinned to a specific version (`==0.1.0`)
2. At least one canonical vector hash from `retention_chain_v0` or `retention_chain_v1` appears in your
   conformance tests — proving you verified against the canonical vectors, not a reimplementation
3. A `NOTICE` file in your project preserving the Apache-2.0 attribution

**To apply:** email **chopmob@gmail.com** with your project's dependency file, a snippet showing
the canonical hash in your test suite, and a copy of your `NOTICE` file. If all criteria are met,
a v0 key is issued within one business day. The key is valid for 12 months and gives access to
`build_audit_report` and the HTTP audit service — `verify_audit_report` is always free with no
key required.

## HTTP service

```bash
pip install "algovoi-retention-chain[serve]"
RETENTION_CHAIN_BIND=0.0.0.0:8096 algovoi-retention-chain
# POST /v1/chain-ref   POST /v1/verify-link   POST /v1/verify-sequence   GET /health
```

### Control-plane federation

The substrate is self-verifiable and needs no issuer trust set to function, but it
integrates with the substrate-2 control plane via `hub_client.py`. Set `S2_HUB_URL`
(and `S2_HUB_TOKEN` to self-register, `POST <hub>/v1/services`) and the service
announces itself so it appears in the control-plane posture alongside the other
substrate-2 services. `S2_HUB_NAME` / `S2_HUB_SELF_URL` override the registered
name and callback URL. A Compliance Command Center bridge is available additively
via the `CCC_HUB_*` environment.

## Acceptance

```bash
python scripts/acceptance.py   # exit 0 + "ALL GREEN"
```

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
