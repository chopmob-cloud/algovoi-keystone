"""algovoi-journey-ref -- content-addressed journey references (Apache-2.0).

Construction and tamper-detection for journey references. The cross-party PROOF
(continuity, scope, completeness) is a separate AlgoVoi component; this package
computes and verifies the reference from its own bytes, fully offline.
"""
from algovoi_journey_ref.journey_ref import (  # noqa: F401
    JourneyRefError, OUTCOMES, SHA256_PREFIX, journey_ref, tamper_detected,
)

__version__ = "0.5.0"
__all__ = ["JourneyRefError", "OUTCOMES", "SHA256_PREFIX", "journey_ref",
           "tamper_detected", "__version__"]
