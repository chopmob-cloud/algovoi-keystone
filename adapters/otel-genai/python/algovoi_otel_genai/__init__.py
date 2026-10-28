"""algovoi-otel-genai -- keystone to OpenTelemetry gen_ai.agent.* adapter (Apache-2.0).

Maps an AlgoVoi keystone decision to the OTel agent-authorization attributes and attaches
execution_ref as an open, recomputable cross-producer key.
"""
from algovoi_otel_genai.adapter import (  # noqa: F401
    OUTCOMES, SHA256_PREFIX, execution_ref, to_gen_ai_attributes, verify_gen_ai_execution_ref,
)

__version__ = "0.1.0"
__all__ = ["OUTCOMES", "SHA256_PREFIX", "execution_ref", "to_gen_ai_attributes",
           "verify_gen_ai_execution_ref", "__version__"]
