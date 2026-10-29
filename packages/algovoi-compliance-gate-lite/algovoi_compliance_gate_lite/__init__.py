"""algovoi-compliance-gate-lite — open, content-addressed compliance decisions, bound to the pinned substrate."""

from algovoi_compliance_gate_lite.compliance_gate_lite import (  # noqa: F401
    SHA256_PREFIX,
    VERDICTS,
    ComplianceGateError,
    gate_ref,
    payer_ref,
    verify,
)

__version__ = "0.4.1"

__all__ = [
    "SHA256_PREFIX",
    "VERDICTS",
    "ComplianceGateError",
    "gate_ref",
    "payer_ref",
    "verify",
    "__version__",
]
