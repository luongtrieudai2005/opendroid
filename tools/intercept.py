"""Intercept workflow: Burp Suite intercept control + mitmproxy integration."""

import json
import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from burp_mcp.client import BurpClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Intercept Rules (for mitmproxy addon)
# ---------------------------------------------------------------------------


@dataclass
class InterceptRule:
    """Rule for modifying intercepted requests/responses via mitmproxy.

    host_pattern: Glob pattern for host matching (e.g. "*.target.com")
    add_headers: Headers to add to request
    remove_headers: Header names to remove from request
    drop: If True, drop the request entirely
    modify_body: Replace body text (simple string replace)
    log_only: If True, only log without modifying
    """
    host_pattern: str = "*"
    add_headers: dict[str, str] = field(default_factory=dict)
    remove_headers: list[str] = field(default_factory=list)
    drop: bool = False
    modify_body: str = ""
    log_only: bool = False


# ---------------------------------------------------------------------------
# Burp Suite Intercept Workaround
# ---------------------------------------------------------------------------


class InterceptSession:
    """Context manager for capturing a request via Burp Suite intercept.

    Uses the toggle-intercept workaround:
    1. enable intercept
    2. wait for user/browser to send request (held by Burp)
    3. disable intercept (forward request)
    4. read latest proxy history entry

    Note: Cannot read/modify the request while it's being intercepted
    (Burp MCP limitation). For full control, use mitmproxy instead.
    """

    def __init__(self, burp_client: BurpClient, wait_time: float = 3.0):
        self.client = burp_client
        self.wait_time = wait_time
        self.history_before: list[dict] | None = None

    def __enter__(self):
        self.client.set_intercept(True)
        logger.info("Intercept ON. Waiting %.1fs for request...", self.wait_time)
        return self

    def __exit__(self, *args):
        self.client.set_intercept(False)
        logger.info("Intercept OFF (request forwarded)")

    def capture(self, timeout: float = 5.0) -> dict[str, Any] | None:
        """Capture the next proxied request by toggling intercept.

        Returns the latest proxy history entry, or None if no request captured.
        """
        # Read history before
        before = self.client.get_proxy_history(offset=0, count=1)

        # Wait for request
        time.sleep(timeout)

        # Forward held request
        self.client.set_intercept(False)
        time.sleep(0.3)

        # Read history after
        after = self.client.get_proxy_history(offset=0, count=1)

        if after and after != before:
            return after
        return None


# ---------------------------------------------------------------------------
# mitmproxy Controller
# ---------------------------------------------------------------------------

_MITMPROXY_ADDON_CODE = r'''
"""mitmproxy addon for AI-controlled interception.

Communicates with the MCP server via a JSON queue file.
"""
import json
import os
import time
from pathlib import Path
from mitmproxy import http


QUEUE_DIR = Path(os.environ.get("MITMPROXY_QUEUE_DIR", "/tmp/mitmproxy_queue"))


class AIInterceptAddon:
    """mitmproxy addon that logs traffic and applies rules from AI."""

    def __init__(self):
        self.rules = []
        self.request_count = 0
        QUEUE_DIR.mkdir(parents=True, exist_ok=True)

    def _load_rules(self):
        rules_file = QUEUE_DIR / "rules.json"
        if rules_file.exists():
            try:
                with open(rules_file) as f:
                    self.rules = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

    def _log_flow(self, flow: http.HTTPFlow, direction: str):
        ts = int(time.time() * 1000)
        log = {
            "timestamp": ts,
            "direction": direction,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "request_headers": dict(flow.request.headers),
            "request_body": flow.request.get_text() if flow.request.content else "",
        }
        if flow.response:
            log["status_code"] = flow.response.status_code
            log["response_headers"] = dict(flow.response.headers)
            log["response_body"] = flow.response.get_text() if flow.response.content else ""

        log_file = QUEUE_DIR / f"{ts}_{self.request_count}_{direction}.json"
        with open(log_file, "w") as f:
            json.dump(log, f)
        self.request_count += 1

    def request(self, flow: http.HTTPFlow):
        self._load_rules()
        host = flow.request.pretty_host

        for rule in self.rules:
            if self._match_host(host, rule.get("host_pattern", "*")):
                if rule.get("drop"):
                    flow.kill()
                    self._log_flow(flow, "dropped")
                    return

                for k, v in rule.get("add_headers", {}).items():
                    flow.request.headers[k] = v
                for h in rule.get("remove_headers", []):
                    flow.request.headers.pop(h, None)

                if rule.get("modify_body"):
                    text = flow.request.get_text() or ""
                    text = text.replace(rule["modify_body"], "")
                    flow.request.set_text(text)

        if not any(r.get("log_only") for r in self.rules if self._match_host(host, r.get("host_pattern", "*"))):
            self._log_flow(flow, "request")

    def response(self, flow: http.HTTPFlow):
        self._log_flow(flow, "response")

    @staticmethod
    def _match_host(host: str, pattern: str) -> bool:
        if pattern == "*" or pattern == "":
            return True
        if pattern.startswith("*."):
            return host.endswith(pattern[1:])
        return host == pattern


addons = [AIInterceptAddon()]
'''


class MitmproxyController:
    """Control mitmproxy as a subprocess.

    mitmproxy sits between the browser and Burp Suite:
        Browser -> mitmproxy (:8081) -> Burp (:8080) -> Internet

    This enables full read/modify/forward/drop of HTTP traffic
    without relying on Burp's limited intercept API.
    """

    def __init__(self, upstream: str = "127.0.0.1:8080",
                 listen_port: int = 8081,
                 queue_dir: str = ""):
        self.upstream = upstream
        self.listen_port = listen_port
        self.queue_dir = queue_dir or os.path.join(
            os.environ.get("TEMP", "/tmp"), "mitmproxy_queue"
        )
        self._process: subprocess.Popen | None = None
        self._addon_path: str = ""

    def start(self) -> bool:
        """Start mitmproxy as a background subprocess.

        Returns True if started successfully.
        """
        if self._process and self._process.poll() is None:
            logger.warning("mitmproxy already running")
            return True

        # Write addon script
        addon_dir = Path(self.queue_dir).parent / "mitmproxy_addons"
        addon_dir.mkdir(parents=True, exist_ok=True)
        addon_path = addon_dir / "ai_intercept_addon.py"
        addon_path.write_text(_MITMPROXY_ADDON_CODE)
        self._addon_path = str(addon_path)

        # Create queue dir
        Path(self.queue_dir).mkdir(parents=True, exist_ok=True)

        # Start mitmproxy
        cmd = [
            "mitmproxy",
            "--mode", f"upstream:http://{self.upstream}",
            "--listen-port", str(self.listen_port),
            "--set", f"block_global=false",
            "-s", self._addon_path,
            "--no-http2",
        ]

        env = os.environ.copy()
        env["MITMPROXY_QUEUE_DIR"] = self.queue_dir

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            time.sleep(1)
            logger.info(
                "mitmproxy started on :%d -> upstream %s",
                self.listen_port, self.upstream,
            )
            return True
        except FileNotFoundError:
            logger.error("mitmproxy not found in PATH. Install: pip install mitmproxy")
            return False

    def stop(self):
        """Stop mitmproxy."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
            logger.info("mitmproxy stopped")

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def set_rules(self, rules: list[InterceptRule]):
        """Set intercept rules for mitmproxy addon.

        Rules are written to a JSON file that the addon reads.
        """
        rules_path = Path(self.queue_dir) / "rules.json"
        rules_data = []
        for r in rules:
            rules_data.append({
                "host_pattern": r.host_pattern,
                "add_headers": r.add_headers,
                "remove_headers": r.remove_headers,
                "drop": r.drop,
                "modify_body": r.modify_body,
                "log_only": r.log_only,
            })
        rules_path.write_text(json.dumps(rules_data, indent=2))
        logger.info("Wrote %d rules to %s", len(rules_data), rules_path)

    def clear_rules(self):
        """Remove all intercept rules."""
        rules_path = Path(self.queue_dir) / "rules.json"
        if rules_path.exists():
            rules_path.unlink()

    def get_logs(self) -> list[dict]:
        """Read and clear captured request/response logs from queue.

        Returns list of log entries.
        """
        logs: list[dict] = []
        queue_dir = Path(self.queue_dir)
        if not queue_dir.exists():
            return logs

        for f in sorted(queue_dir.glob("*.json")):
            if f.name == "rules.json":
                continue
            try:
                logs.append(json.loads(f.read_text()))
            except (json.JSONDecodeError, OSError):
                pass
            try:
                f.unlink()
            except OSError:
                pass

        return logs

    @staticmethod
    def install_ca_cert() -> str:
        """Get path to mitmproxy CA certificate for installation.

        Returns path to the PEM certificate, or empty string if not found.
        """
        candidates = [
            Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem",
            Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer",
        ]
        for p in candidates:
            if p.exists():
                return str(p)
        return ""

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
