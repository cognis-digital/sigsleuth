"""SIGSLEUTH MCP server — exposes decode operations as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from sigsleuth.core import decode_calldata, decode_eip712, SigsleuthError


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
        """Decodes raw calldata and EIP-712 typed-data into human-readable intent,
        flagging blind-signing and malicious permit/Permit2 payloads.
        Returns JSON findings.
        """
        if not isinstance(target, str) or not target.strip():
            return json.dumps({"error": "target must be a non-empty string"})
        raw = target.strip()
        try:
            # Heuristic: JSON objects are EIP-712, hex strings are calldata.
            if raw.startswith("{"):
                result = decode_eip712(raw)
            else:
                result = decode_calldata(raw)
            return json.dumps(result, indent=2)
        except SigsleuthError as exc:
            return json.dumps({"error": str(exc)})

    app.run()
    return 0
