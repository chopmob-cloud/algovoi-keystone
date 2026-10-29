"""algovoi-execution-ref: decision-bound execution evidence, bound to the keystone.

Runs on any substrate version (v0 / v1): it uses only the stable JCS
canonicalisation. Install alongside your existing substrate and use execution_ref
and the keystone with no substrate upgrade required.
"""

from algovoi_execution_ref.refs import (
    ExecutionRefError,
    EXECUTION_OUTCOMES,
    DECISION_VERDICTS,
    TRUST_OUTCOMES,
    execution_ref,
    decision_ref,
    trust_query_ref,
    execution_binding,
    bind_keystone,
    verify_record,
)

__version__ = "0.5.0"

__all__ = [
    "ExecutionRefError",
    "EXECUTION_OUTCOMES", "DECISION_VERDICTS", "TRUST_OUTCOMES",
    "execution_ref", "decision_ref", "trust_query_ref",
    "execution_binding", "bind_keystone", "verify_record",
    "__version__",
]
