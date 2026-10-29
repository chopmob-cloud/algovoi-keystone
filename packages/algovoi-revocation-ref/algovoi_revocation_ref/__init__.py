"""algovoi-revocation-ref -- content-addressed revocation references (Apache-2.0).

Construction, tamper-detection and chain verification for revocation references.
The revocation-cascade PROOF is a separate AlgoVoi component; this package
computes and verifies the reference (and its chain) from its own bytes, offline.
"""
from algovoi_revocation_ref.revocation_ref import (  # noqa: F401
    REASONS, RevocationRefError, SHA256_PREFIX, revocation_ref, tamper_detected, verify_chain,
)

__version__ = "0.4.2"
__all__ = ["REASONS", "RevocationRefError", "SHA256_PREFIX", "revocation_ref",
           "tamper_detected", "verify_chain", "__version__"]
