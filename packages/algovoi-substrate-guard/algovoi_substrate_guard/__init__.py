"""algovoi-substrate-guard — deterministic input-bounds / DoS hardening gate for the AlgoVoi substrate."""

from algovoi_substrate_guard.guard import (  # noqa: F401
    DEFAULT_PROFILE,
    GuardError,
    Profile,
    guard,
    profile_ref,
)

__version__ = "0.4.0"

__all__ = [
    "DEFAULT_PROFILE",
    "GuardError",
    "Profile",
    "guard",
    "profile_ref",
    "__version__",
]
