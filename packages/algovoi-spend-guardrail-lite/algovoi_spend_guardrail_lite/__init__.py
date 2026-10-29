"""algovoi-spend-guardrail-lite — open, content-addressed pre-payment decisions, bound to the pinned substrate."""

from algovoi_spend_guardrail_lite.spend_guardrail_lite import (  # noqa: F401
    SHA256_PREFIX,
    VERDICTS,
    SpendGuardrailError,
    guardrail_ref,
    verify,
)

__version__ = "0.4.1"

__all__ = [
    "SHA256_PREFIX",
    "VERDICTS",
    "SpendGuardrailError",
    "guardrail_ref",
    "verify",
    "__version__",
]
