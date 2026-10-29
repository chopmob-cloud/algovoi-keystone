"""algovoi-delegation-ref — content-addressed delegation references for the AlgoVoi substrate."""

from algovoi_delegation_ref.delegation_ref import (  # noqa: F401
    DelegationRefError,
    SHA256_PREFIX,
    delegation_ref,
    tamper_detected,
    verify_chain,
)

__version__ = "0.5.0"

__all__ = [
    "DelegationRefError",
    "SHA256_PREFIX",
    "delegation_ref",
    "tamper_detected",
    "verify_chain",
    "__version__",
]
