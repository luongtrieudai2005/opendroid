"""Entry point for running the MCP server.

Usage:
    python -m mcp_server              # stdio mode (default, for opencode)
    python -m mcp_server --sse        # SSE mode (standalone on port 9878)
"""

import argparse
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from mcp_server import mcp


def run_stdio():
    mcp.run(transport="stdio")


def run_sse():
    import uvicorn
    print("=" * 55)
    print("  BUG BOUNTY MCP SERVER (SSE)")
    print("  Listening on http://0.0.0.0:9878/sse")
    print("=" * 55)
    app = mcp.sse_app()
    uvicorn.run(app, host="0.0.0.0", port=9878, log_level="info")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bug Bounty MCP Server")
    parser.add_argument("--sse", action="store_true", help="Run in SSE mode (standalone)")
    args = parser.parse_args()

    if args.sse:
        run_sse()
    else:
        run_stdio()
