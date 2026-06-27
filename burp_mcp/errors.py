class BurpConnectionError(Exception):
    """Cannot connect to Burp MCP server."""


class BurpTimeoutError(Exception):
    """No response received from Burp MCP server."""


class BurpToolError(Exception):
    """MCP tool call failed (wrong params, pro-only, etc.)."""
