"""Entry point for running the MCP server.

Usage:
    python -m mcp_server
"""

import logging
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from mcp_server import mcp

if __name__ == "__main__":
    print("=" * 55)
    print("  BUG BOUNTY MCP SERVER")
    print("  Listening on http://0.0.0.0:9878/sse")
    print("=" * 55)
    app = mcp.sse_app()
    uvicorn.run(app, host="0.0.0.0", port=9878, log_level="info")
