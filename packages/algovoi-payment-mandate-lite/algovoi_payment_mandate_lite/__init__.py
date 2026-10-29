"""algovoi-payment-mandate-lite — open, content-addressed spend-authority references, bound into the pinned substrate."""

from algovoi_payment_mandate_lite.payment_mandate_lite import (  # noqa: F401
    SHA256_PREFIX,
    PaymentMandateError,
    mandate_ref,
    verify,
)

__version__ = "0.4.1"

__all__ = [
    "SHA256_PREFIX",
    "PaymentMandateError",
    "mandate_ref",
    "verify",
    "__version__",
]
