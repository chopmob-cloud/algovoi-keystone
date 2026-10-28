# algovoi-composite-trust-query-lite

Open, content-addressed **trust-verdict references** for the AlgoVoi substrate. The lite, Apache-2.0 origination tier of the commercial AlgoVoi Composite Trust Query. It **caps the open decision/receipt lifecycle**: one recomputable address binds a categorical trust answer to the exact set of references it was computed over.

```
trust_query_ref = "sha256:" + SHA-256(JCS({ subject_refs, trust_outcome }))
```

- **`subject_refs`**: the ordered list of references the verdict was reached over, each imported by hash (e.g. the `passport_ref`, `mandate_ref`, `policy_bound_ref` and `guardrail_ref` of a decision chain). **Order and membership are both byte-load-bearing.**
- **`trust_outcome`**: a closed enum: `TRUSTED`, `PROVISIONAL`, `INSUFFICIENT_EVIDENCE`, `UNTRUSTED`.

Change which references were assessed, their order, or the verdict, and the `trust_query_ref` diverges, so a verdict cannot be re-pointed to a different set or silently drop a reference it claimed to assess. An outcome outside the enum, an empty list, or an empty member is rejected, not hashed.

**Lite binds only.** This package content-addresses the binding; the scoring and verification that *produce* the verdict stay commercial.

## Use

```python
from algovoi_composite_trust_query_lite import trust_query_ref

ref = trust_query_ref(
    subject_refs=[
        "sha256:b3594e33998af01bd1ad208172c5c1ac586daa8c75781379f034d97e50b1a9be",  # passport_ref
        "sha256:a4f8cb5ee09b29478ac1cc2f468d66e16d3d25f7a229a31d22ad521e11d04d35",  # mandate_ref
        "sha256:aaee2091799f376ee8cac802ea4920feaa4eca52950488a3e047ff82e6959a21",  # policy_bound_ref
        "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97",  # guardrail_ref (ALLOW)
    ],
    trust_outcome="TRUSTED",
)
```

## Lite vs commercial

| | Lite (this package) | Commercial Composite Trust Query |
|---|---|---|
| Licence | Apache-2.0, open | Commercial OEM |
| Reference | content-addressed `trust_query_ref` (binding only) | the same, **Falcon-1024 signed verdict** |
| Scoring | bring your own | walks the audit chain, checks revocation/reversal/termination |
| Verifier | recompute the binding offline | maintained verifier under asserted jurisdictions |

## Adopters (pin → key)

If you build on `algovoi-composite-trust-query-lite`, pin `==0.1.0`, anchor a canonical `trust_query_ref` vector hash from `composite_trust_query_lite_v1`, and keep the `NOTICE`, you qualify for a free **v0 licence key** for `algovoi-mandate-auditor`. The gate is `scripts/check_v0_adoption.py`. Apply: email chopmob@gmail.com with your import-by-hash evidence and a copy of the NOTICE.

## Conformance

The `composite_trust_query_lite_v1` vector set is published in the public corpus,
[chopmob-cloud/algovoi-jcs-conformance-vectors](https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors),
with Python and Node runners. Python and TypeScript reproduce every value byte-for-byte. `tq-001`, `tq-002` and `tq-003` cap the live decision chain in `spend_decision_chain_v1`.

Apache-2.0. Additive over the frozen canonicalisation substrate; sole AlgoVoi authorship.
