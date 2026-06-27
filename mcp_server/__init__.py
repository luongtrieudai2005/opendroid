"""MCP Server for Bug Bounty automation.

Run with: python -m mcp_server
"""

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from mcp_server.server import mcp
from mcp_server import tools_registry  # noqa: F401 - registers tools

__all__ = ["mcp"]
