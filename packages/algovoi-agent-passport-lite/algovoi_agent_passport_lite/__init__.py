"""algovoi-agent-passport-lite — open, content-addressed agent identity references, bound into the pinned substrate."""

from algovoi_agent_passport_lite.agent_passport_lite import (  # noqa: F401
    SHA256_PREFIX,
    AgentPassportError,
    passport_ref,
    verify,
)

__version__ = "0.4.1"

__all__ = [
    "SHA256_PREFIX",
    "AgentPassportError",
    "passport_ref",
    "verify",
    "__version__",
]
