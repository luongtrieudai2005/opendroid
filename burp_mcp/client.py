"""MCP client for BurpSuite MCP Server.

Communicates via SSE (Server-Sent Events) + POST JSON-RPC.
Uses curl.exe subprocess (verified working on Windows).
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from typing import Any

from .errors import BurpConnectionError

logger = logging.getLogger(__name__)


class BurpClient:
    """Client for BurpSuite MCP Server."""

    def __init__(self, mcp_url: str = "http://127.0.0.1:9876"):
        self.mcp_url = mcp_url.rstrip("/")
        self.session_id: str | None = None
        self._sse_proc: subprocess.Popen | None = None
        self._sse_thread: threading.Thread | None = None
        self._responses: dict[int, dict] = {}
        self._lock = threading.Lock()
        self._msg_counter = 0
        self._closed = False

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self, timeout: int = 5) -> bool:
        """Open SSE connection and get session ID from the first endpoint event.

        Starts the persistent SSE listener which captures the session ID
        from the initial 'endpoint' SSE event. This ensures POST requests
        use the same session as the response stream.

        Returns True on success.
        """
        logger.info("Connecting to Burp MCP at %s ...", self.mcp_url)
        try:
            subprocess.run(
                ["curl.exe", "-s", "--max-time", "2", f"{self.mcp_url}/"],
                capture_output=True, timeout=4,
            )
        except FileNotFoundError:
            raise BurpConnectionError("curl.exe not found in PATH")

        # Start SSE listener (it captures session ID from endpoint event)
        self._start_sse_listener()

        # Wait for session ID
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self.session_id:
                    break
            time.sleep(0.1)

        if not self.session_id:
            raise BurpConnectionError(
                "Could not get session ID from SSE stream. "
                "Is BurpSuite MCP server running?"
            )

        logger.info("Session ID: %s", self.session_id)
        return True

    def _start_sse_listener(self):
        """Start background thread that keeps SSE connection alive.

        Uses curl.exe -N (no-buffer) to maintain a persistent GET connection.
        Captures session ID from the initial 'endpoint' SSE event.
        All subsequent 'message' events (JSON-RPC responses) are dispatched
        and matched to requests by message id.
        """
        self._sse_proc = subprocess.Popen(
            ["curl.exe", "-s", "-N", f"{self.mcp_url}/"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        def _read_sse():
            event_type = None
            data_buf: list[str] = []
            try:
                for line in iter(self._sse_proc.stdout.readline, ""):
                    if self._closed:
                        break
                    line = line.strip()
                    if not line:
                        if event_type == "endpoint" and data_buf:
                            raw = "".join(data_buf)
                            m = re.search(r"sessionId=([a-f0-9-]+)", raw)
                            if m:
                                with self._lock:
                                    if not self.session_id:
                                        self.session_id = m.group(1)
                        elif event_type == "message" and data_buf:
                            self._dispatch_message("".join(data_buf))
                        event_type = None
                        data_buf = []
                    elif line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data_buf.append(line[5:].strip())
            except Exception:
                if not self._closed:
                    logger.warning("SSE listener error", exc_info=True)

        self._sse_thread = threading.Thread(target=_read_sse, daemon=True)
        self._sse_thread.start()

    def _dispatch_message(self, raw: str):
        """Parse JSON-RPC message from SSE and store in response dict.

        Only messages with an 'id' field are stored (responses to our requests).
        Notifications (JSON-RPC without id) are silently dropped.
        """
        try:
            msg = json.loads(raw)
            mid = msg.get("id")
            if mid is not None:
                with self._lock:
                    self._responses[mid] = msg
        except json.JSONDecodeError:
            logger.warning("Invalid SSE message: %s", raw[:100])

    # ------------------------------------------------------------------
    # JSON-RPC calls
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._msg_counter += 1
        return self._msg_counter

    def send_request(self, method: str, params: dict | None = None) -> dict | None:
        """Send JSON-RPC request and wait for response (up to 8s)."""
        if not self.session_id:
            raise BurpConnectionError("Not connected. Call connect() first.")

        msg_id = self._next_id()
        url = f"{self.mcp_url}/?sessionId={self.session_id}"
        body = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params:
            body["params"] = params

        # Write body to temp file to avoid shell escaping issues
        tmp = os.path.join(
            os.environ.get("TEMP", "."), f"burp_mcp_{msg_id}_{int(time.time())}.json"
        )
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(body, f)

            subprocess.run(
                [
                    "curl.exe", "-s", "--max-time", "5", "-X", "POST", url,
                    "-H", "Content-Type: application/json",
                    "-d", f"@{tmp}",
                ],
                capture_output=True,
                timeout=6,
            )
        except subprocess.TimeoutExpired:
            logger.warning("POST timeout for id=%s", msg_id)
            return None
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

        # Wait for SSE response
        deadline = time.time() + 8.0
        while time.time() < deadline:
            with self._lock:
                if msg_id in self._responses:
                    return self._responses.pop(msg_id).get("result")
            time.sleep(0.05)

        logger.warning("No SSE response for id=%s (method=%s)", msg_id, method)
        return None

    def call_tool(self, name: str, arguments: dict | None = None) -> dict | None:
        """Call an MCP tool by name."""
        params: dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = arguments
        return self.send_request("tools/call", params)

    def initialize(self) -> dict | None:
        """Initialize MCP session (must be called once after connect)."""
        return self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "burp-mcp-client", "version": "1.0.0"},
        })

    def list_tools(self) -> list[dict] | None:
        """List available MCP tools."""
        result = self.send_request("tools/list")
        if result and "tools" in result:
            return result["tools"]
        return None

    # ------------------------------------------------------------------
    # High-level tool wrappers
    # ------------------------------------------------------------------

    def send_http1_request(
        self,
        content: str,
        hostname: str,
        port: int,
        https: bool,
    ) -> dict | None:
        """Send an HTTP/1.1 request through Burp."""
        return self.call_tool("send_http1_request", {
            "content": content,
            "targetHostname": hostname,
            "targetPort": port,
            "usesHttps": https,
        })

    def send_http2_request(
        self,
        pseudo_headers: dict[str, str],
        headers: dict[str, str],
        body: str,
        hostname: str,
        port: int,
        https: bool,
    ) -> dict | None:
        """Send an HTTP/2 request through Burp."""
        return self.call_tool("send_http2_request", {
            "pseudoHeaders": pseudo_headers,
            "headers": headers,
            "requestBody": body,
            "targetHostname": hostname,
            "targetPort": port,
            "usesHttps": https,
        })

    def get_proxy_history(
        self, offset: int = 0, count: int = 10
    ) -> dict | None:
        """Get proxy HTTP history."""
        return self.call_tool("get_proxy_http_history", {
            "offset": offset,
            "count": count,
        })

    def get_proxy_history_regex(
        self, regex: str, offset: int = 0, count: int = 10
    ) -> dict | None:
        """Get proxy HTTP history filtered by regex."""
        return self.call_tool("get_proxy_http_history_regex", {
            "regex": regex,
            "offset": offset,
            "count": count,
        })

    def set_intercept(self, enabled: bool) -> dict | None:
        """Enable or disable proxy intercept."""
        return self.call_tool("set_proxy_intercept_state", {
            "intercepting": enabled,
        })

    def get_active_editor(self) -> dict | None:
        """Get contents of the active editor (requires UI focus)."""
        return self.call_tool("get_active_editor_contents")

    def set_active_editor(self, text: str) -> dict | None:
        """Set contents of the active editor (requires UI focus)."""
        return self.call_tool("set_active_editor_contents", {"text": text})

    def create_repeater(
        self,
        content: str,
        hostname: str,
        port: int,
        https: bool,
        tab_name: str | None = None,
    ) -> dict | None:
        """Create a Repeater tab with the given request."""
        args = {
            "content": content,
            "targetHostname": hostname,
            "targetPort": port,
            "usesHttps": https,
        }
        if tab_name:
            args["tabName"] = tab_name
        return self.call_tool("create_repeater_tab", args)

    def send_to_intruder(
        self,
        content: str,
        hostname: str,
        port: int,
        https: bool,
        tab_name: str | None = None,
    ) -> dict | None:
        """Send request to Intruder. ⚠️ Has duplicate Host header bug."""
        args = {
            "content": content,
            "targetHostname": hostname,
            "targetPort": port,
            "usesHttps": https,
        }
        if tab_name:
            args["tabName"] = tab_name
        return self.call_tool("send_to_intruder", args)

    def get_organizer_items(self, offset: int = 0, count: int = 10) -> dict | None:
        """Get items from Organizer tab."""
        return self.call_tool("get_organizer_items", {
            "offset": offset,
            "count": count,
        })

    def set_task_engine(self, running: bool) -> dict | None:
        """Pause or resume Burp's task execution engine."""
        return self.call_tool("set_task_execution_engine_state", {
            "running": running,
        })

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self):
        """Close SSE connection and clean up."""
        self._closed = True
        if self._sse_proc:
            try:
                self._sse_proc.kill()
            except Exception:
                pass
            self._sse_proc = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
