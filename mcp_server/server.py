"""Bug Bounty MCP Server for opencode.

Exposes BurpSuite + recon + analysis + fuzzing capabilities as MCP tools.
"""

import logging
import os
import sys
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
from burp_mcp.client import BurpClient
from burp_mcp.errors import BurpConnectionError

logger = logging.getLogger(__name__)

# Global Burp client instance (initialized during lifespan)
_burp: BurpClient | None = None


def get_burp() -> BurpClient | None:
    """Get the shared BurpClient instance, or None if Burp is unavailable."""
    global _burp
    if _burp is None:
        try:
            _burp = BurpClient()
            _burp.connect()
            _burp.initialize()
        except BurpConnectionError:
            logger.warning("Burp MCP not available. Run BurpSuite with MCP extension on port 9876.")
            return None
    return _burp


@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Manage server lifecycle: connect to Burp on startup, disconnect on shutdown."""
    global _burp
    logger.info("Bug Bounty MCP Server starting...")
    try:
        _burp = BurpClient()
        _burp.connect()
        _burp.initialize()
        logger.info("Connected to Burp MCP")
    except BurpConnectionError as e:
        logger.warning("Burp MCP not available: %s", e)
        _burp = None
    try:
        yield {}
    finally:
        if _burp:
            _burp.close()
        logger.info("Bug Bounty MCP Server stopped")


# Create MCP server
mcp = FastMCP(
    "Bug Bounty Hunter",
    instructions="""Bug bounty automation via BurpSuite MCP.

Available capabilities:
- Send HTTP requests through Burp Suite
- Read proxy history
- Analyze responses for vulnerabilities
- Run recon pipeline (subdomains, HTTP probing, nuclei scanning)
- Fuzz parameters (XSS, SQLi, path discovery)
- Android APK analysis (decompile, extract secrets, endpoints)
- Bypass SSL pinning via Frida
- Generate bug bounty reports

Use burp_connect() first to verify connection.
""",
    lifespan=server_lifespan,
)
