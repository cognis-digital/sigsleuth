"""SIGSLEUTH MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from sigsleuth.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-sigsleuth[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-sigsleuth[mcp]'")
        return 1
    app = FastMCP("sigsleuth")

    @app.tool()
    def sigsleuth_scan(target: str) -> str:
        """Decodes raw calldata and EIP-712 typed-data into human-readable intent, flagging blind-signing and malicious permit/Permit2 payloads.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
