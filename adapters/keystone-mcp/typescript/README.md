# algovoi-keystone-mcp

An open [MCP](https://modelcontextprotocol.io) server exposing keystone verification as tools, so
any MCP client can recompute and check a keystone `execution_ref` offline. Two tools:
`keystone_execution_ref` (recompute) and `keystone_verify` (recompute + compare to a claimed value).
Pure and open: JCS (RFC 8785) + SHA-256, no AlgoVoi service, not the private composition engine.

```bash
pip install "algovoi-keystone-mcp[server]"
python -m algovoi_keystone_mcp        # stdio MCP server
```

```python
from algovoi_keystone_mcp import verify_execution_ref
verify_execution_ref(dr, "payment", "payments/transfer", "COMMITTED", 1716460800000, claimed)["ok"]
```

Apache-2.0.
