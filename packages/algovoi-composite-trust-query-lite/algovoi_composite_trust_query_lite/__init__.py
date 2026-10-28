"""algovoi-composite-trust-query-lite — open, content-addressed trust-verdict references, bound into the pinned substrate."""

from algovoi_composite_trust_query_lite.composite_trust_query_lite import (  # noqa: F401
    TRUST_OUTCOMES,
    SHA256_PREFIX,
    CompositeTrustQueryError,
    trust_query_ref,
    verify,
)

__version__ = "0.4.0"

__all__ = [
    "TRUST_OUTCOMES",
    "SHA256_PREFIX",
    "CompositeTrustQueryError",
    "trust_query_ref",
    "verify",
    "__version__",
]
