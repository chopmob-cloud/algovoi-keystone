"""algovoi-cancellation-receipt-lite — open, content-addressed cancellation references, bound into the pinned substrate."""

from algovoi_cancellation_receipt_lite.cancellation_receipt_lite import (  # noqa: F401
    REASONS,
    SHA256_PREFIX,
    CancellationReceiptError,
    cancellation_ref,
    verify,
)

__version__ = "0.5.0"

__all__ = [
    "REASONS",
    "SHA256_PREFIX",
    "CancellationReceiptError",
    "cancellation_ref",
    "verify",
    "__version__",
]
