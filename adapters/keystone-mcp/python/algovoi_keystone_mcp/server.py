"""algovoi-keystone-mcp -- an open Model Context Protocol (MCP) server exposing keystone
verification as tools, so any MCP client (an agent, an IDE) can recompute and check a keystone
execution_ref offline.

Two tools, both pure and open (no AlgoVoi service, no private engine):
  - keystone_execution_ref(decision_ref, action_type, scope, outcome, executed_at_ms) -> str
  - keystone_verify(decision_ref, action_type, scope, outcome, executed_at_ms,
                    claimed_execution_ref) -> {ok, computed, claimed}

Run:  python -m algovoi_keystone_mcp   (stdio MCP server)

Requires the optional ``fastmcp`` extra. Apache-2.0.
"""
from __future__ import annotations

from algovoi_keystone_mcp.verify import execution_ref as _execution_ref
from algovoi_keystone_mcp.verify import verify_execution_ref as _verify_execution_ref


def build_server():
    """Construct the FastMCP server with the two keystone verification tools registered."""
    from fastmcp import FastMCP

    mcp = FastMCP("algovoi-keystone")

    @mcp.tool()
    def keystone_execution_ref(decision_ref: str, action_type: str, scope: str, outcome: str,
                               executed_at_ms: int) -> str:
        """Recompute the decision-bound keystone execution_ref from its fields (JCS + SHA-256)."""
        return _execution_ref(decision_ref, action_type, scope, outcome, executed_at_ms)

    @mcp.tool()
    def keystone_verify(decision_ref: str, action_type: str, scope: str, outcome: str,
                        executed_at_ms: int, claimed_execution_ref: str) -> dict:
        """Recompute the keystone execution_ref and confirm it matches a claimed value.
        Returns {ok, computed, claimed}; ok is True only on a byte-exact match."""
        return _verify_execution_ref(decision_ref, action_type, scope, outcome, executed_at_ms,
                                     claimed_execution_ref)

    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
