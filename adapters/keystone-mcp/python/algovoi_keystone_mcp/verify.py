"""algovoi-keystone-mcp -- the open keystone verification core.

Pure functions (no MCP, no service) that recompute and verify the decision-bound execution_ref:

    execution_ref = "sha256:" + SHA-256(JCS(RFC 8785)({decision_ref, action_type, scope, outcome,
                                                       executed_at_ms}))

These are what the MCP server (server.py) exposes as tools. This module is the OPEN verifier: it
recomputes the content-addressed reference; it does NOT run the cross-party composition engine.
Apache-2.0.
"""
from __future__ import annotations

from algovoi_substrate import sha256_jcs

SHA256_PREFIX = "sha256:"

__all__ = ["SHA256_PREFIX", "execution_ref", "verify_execution_ref"]


def execution_ref(decision_ref: str, action_type: str, scope: str, outcome: str,
                  executed_at_ms: int) -> str:
    """Recompute the decision-bound execution_ref from its fields."""
    return SHA256_PREFIX + sha256_jcs({
        "decision_ref": decision_ref, "action_type": action_type, "scope": scope,
        "outcome": outcome, "executed_at_ms": int(executed_at_ms),
    })


def verify_execution_ref(decision_ref: str, action_type: str, scope: str, outcome: str,
                         executed_at_ms: int, claimed_execution_ref: str) -> dict:
    """Recompute execution_ref and compare to a claimed value. Returns {ok, computed, claimed}.
    Fail-closed: any malformed field yields ok=False."""
    try:
        computed = execution_ref(decision_ref, action_type, scope, outcome, int(executed_at_ms))
    except (TypeError, ValueError):
        return {"ok": False, "computed": None, "claimed": claimed_execution_ref}
    return {"ok": computed == claimed_execution_ref, "computed": computed, "claimed": claimed_execution_ref}
