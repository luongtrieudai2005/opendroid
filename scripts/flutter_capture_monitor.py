"""Flutter TLS-bypass capture monitor.

Keeps a persistent NVISO ``disable_flutter_tls.js`` Frida hook attached to a
running Flutter app so Burp can MITM the app's Dart-core (BoringSSL) traffic.

The hook patches ``ssl_verify_peer_cert`` in ``libflutter.so`` so BoringSSL
skips certificate verification. Combined with an iptables DNAT on the device
(redirecting outbound 443/80 to a Burp invisible proxy listener), traffic from
``dart:io`` becomes visible in Burp.

Why this exists:
    The Frida process started from a short-lived shell dies with the shell,
    silently removing the TLS bypass. This script supervises the full chain
    (frida-server -> app -> frida client) and auto-restarts what is missing.

Typical usage::

    python scripts/flutter_capture_monitor.py            # default: loop 10s
    python scripts/flutter_capture_monitor.py --once     # single check cycle
    python scripts/flutter_capture_monitor.py --port 27043

The script does NOT touch iptables or the system proxy by default (pass
``--ensure-env`` to also re-assert those).
"""

import argparse
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("flutter-capture")

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NVISO_SCRIPT = (PROJECT_ROOT / "config" / "frida-scripts" / "flutter"
                / "disable_flutter_tls.js")
FRIDA_SERVER_REMOTE = "/data/local/tmp/frida-server"
LOG_PATH = PROJECT_ROOT / "workspace" / "flutter_capture.log"

# Target-specific values come from CLI arguments (see main()).
PACKAGE: str = ""
PROCESS_NAME: str = ""
MAIN_ACTIVITY: str = ""
PROXY_TARGET: str = ""
FRIDA_HOST = "127.0.0.1"
FRIDA_PORT = 27042
ATCH_SUCCESS_TOKENS = ("ssl_verify_peer_cert has been patched",
                       "ssl_verify_peer_cert found")
LOOP_INTERVAL = 10
VERIFY_TIMEOUT = 20
ATTACH_BACKOFF = 90

ADB = shutil.which("adb") or "adb"
FRIDA = shutil.which("frida") or "frida"

_ATTACH_PID: int | None = None
_APP_PID: str | None = None
_last_attach_ts: float | None = None


def _adb(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run an adb command and return the result."""
    return subprocess.run([ADB, "-s", "emulator-5554", *args],
                          capture_output=True, text=True, timeout=timeout)


def frida_server_running() -> bool:
    """Check the frida-server process exists on the device."""
    out = _adb("shell", "ps -A | grep frida-server").stdout
    return bool(out.strip())


def app_running() -> bool:
    """Check the target app process exists on the device."""
    out = _adb("shell", f"ps -A | grep {PACKAGE}").stdout
    return bool(out.strip())


def app_pid() -> str:
    """Return the app's current PID (or empty string if not running)."""
    out = _adb("shell", f"ps -A | grep {PACKAGE}").stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            return parts[1]
    return ""


def start_frida_server() -> bool:
    """Start frida-server on the device listening on 0.0.0.0:<port>."""
    if not _adb("shell", f"ls {FRIDA_SERVER_REMOTE}").returncode == 0:
        local = PROJECT_ROOT / "config" / "frida-server"
        if not local.exists():
            logger.error("frida-server binary missing: %s", local)
            return False
        _adb("push", str(local), FRIDA_SERVER_REMOTE)
    _adb("shell", "chmod 755 " + FRIDA_SERVER_REMOTE)
    _adb("shell", f"nohup {FRIDA_SERVER_REMOTE} -D -l 0.0.0.0:{FRIDA_PORT} "
                  "> /dev/null 2>&1 &")
    time.sleep(2)
    if not frida_server_running():
        logger.error("Failed to start frida-server")
        return False
    logger.info("frida-server started")
    return True


def start_app() -> bool:
    """Launch the app if not already running; return True if running."""
    if app_running():
        return True
    _adb("shell", f"am start -n {MAIN_ACTIVITY}")
    time.sleep(5)
    if not app_running():
        logger.error("App did not start")
        return False
    logger.info("App started: %s", PACKAGE)
    return True


def frida_attached() -> bool:
    """Check whether a frida client process is currently attached."""
    if _ATTACH_PID is None:
        return False
    proc = _get_process(_ATTACH_PID)
    if proc is None:
        return False
    return True


def _get_process(pid: int):
    """Return a psutil-like handle via tasklist if windows, else None."""
    import platform
    if platform.system() == "Windows":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout if str(pid) in out.stdout else None
    try:
        import psutil
        return psutil.Process(pid)
    except Exception:
        return None


def _capture_healthy() -> bool:
    """A capture is healthy if the NVISO log shows a successful patch."""
    if not LOG_PATH.exists() or LOG_PATH.stat().st_size == 0:
        return False
    text = LOG_PATH.read_text(encoding="utf-8", errors="ignore")
    return any(tok in text for tok in ATCH_SUCCESS_TOKENS)


def _kill_previous_attach() -> None:
    """Terminate any frida.exe client processes (console stubs).

    Each re-attach spawns a fresh frida console client that keeps a visible
    window open while attached. This workflow uses a single supervised attach,
    so we sweep all of them before (re)spawning.
    """
    global _ATTACH_PID
    out = subprocess.run(["taskkill", "/IM", "frida.exe", "/F"],
                         capture_output=True, timeout=15)
    text = (out.stdout + out.stderr).decode("utf-8", "replace").lower()
    if "successfully" in text:
        logger.info("Cleaned up pre-existing frida.exe clients")
    _ATTACH_PID = None


def attach_frida(once: bool = False) -> bool:
    """Attach the NVISO script to the app via Frida (device mode).

    Returns True when the patch was applied successfully.
    """
    if not NVISO_SCRIPT.exists():
        logger.error("NVISO script missing: %s", NVISO_SCRIPT)
        return False

    # Fresh log so health checks reflect this attach attempt.
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("", encoding="utf-8")

    _kill_previous_attach()

    cmd = [FRIDA, "-H", f"{FRIDA_HOST}:{FRIDA_PORT}",
           "-n", PROCESS_NAME, "-l", str(NVISO_SCRIPT), "-o", str(LOG_PATH)]
    logger.info("Attaching Frida: %s ...", " ".join(cmd[:6]))

    try:
        # Frida exits when run with no TTY (quiet mode / piped stdin), so we
        # launch it hidden-but-interactive: hidden console window via
        # STARTF_USESHOWWINDOW, keep an inherited stdin so the REPL stays up.
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        proc = subprocess.Popen(
            cmd,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0),
            cwd=str(PROJECT_ROOT), startupinfo=si)
    except Exception as exc:  # pragma: no cover - platform guard
        logger.error("Failed to launch frida: %s", exc)
        return False

    global _ATTACH_PID
    _ATTACH_PID = proc.pid

    # Poll the log for the success marker (NVISO prints it when patched).
    deadline = time.time() + VERIFY_TIMEOUT
    while time.time() < deadline:
        if _capture_healthy():
            logger.info("NVISO hook attached & patched (pid=%s)", proc.pid)
            return True
        if proc.poll() is not None:
            logger.warning("Frida exited rc=%s", proc.returncode)
            break
        time.sleep(1)

    logger.error("Attach verify timeout - frida rc=%s", proc.returncode)
    return False


def ensure_env() -> None:
    """Re-assert iptables DNAT and system proxy (optional, opt-in)."""
    target = PROXY_TARGET
    if not target:
        logger.warning("--proxy not given; skipping iptables DNAT")
        return
    _adb("shell", f"iptables -t nat -C OUTPUT -p tcp --dport 443 "
                  f"-j DNAT --to-destination {target} 2>/dev/null "
                  f"|| iptables -t nat -A OUTPUT -p tcp --dport 443 "
                  f"-j DNAT --to-destination {target}")
    _adb("shell", f"iptables -t nat -C OUTPUT -p tcp --dport 80 "
                  f"-j DNAT --to-destination {target} 2>/dev/null "
                  f"|| iptables -t nat -A OUTPUT -p tcp --dport 80 "
                  f"-j DNAT --to-destination {target}")
    _adb("shell", "settings put global http_proxy " + target)
    logger.info("Environment re-asserted: proxy + DNAT -> %s", target)


def cycle(once: bool = False) -> bool:
    """Run one supervision cycle; return True if the chain is healthy."""
    global _APP_PID, _last_attach_ts
    ok = True

    if not frida_server_running():
        logger.warning("frida-server down -> restarting")
        ok = start_frida_server() and ok
        time.sleep(2)

    if not app_running():
        logger.warning("App not running -> starting")
        ok = start_app() and ok
        time.sleep(2)

    app_changed = app_pid() != _APP_PID
    if app_changed:
        logger.info("App PID changed (was=%s now=%s) -> re-attaching",
                    _APP_PID, app_pid())
        _APP_PID = app_pid()

    need_attach = (not frida_attached()) or app_changed or not _capture_healthy()
    if need_attach:
        # Backoff: avoid hammering attach every loop when it keeps failing
        # (which previously spawned a new frida.exe window each cycle).
        since = time.time() - _last_attach_ts if _last_attach_ts else 999
        if since >= ATTACH_BACKOFF:
            logger.warning("NVISO hook unhealthy -> re-attaching")
            ok = attach_frida(once=once or app_changed) and ok
            _last_attach_ts = time.time()
        else:
            logger.warning("NVISO hook unhealthy, retrying in %ds "
                           "(backoff %ds)", int(ATTACH_BACKOFF - since),
                           ATTACH_BACKOFF)
    else:
        logger.debug("NVISO hook healthy (pid=%s)", _ATTACH_PID)

    return ok


def main() -> int:
    """Entry point."""
    global FRIDA_PORT, PACKAGE, PROCESS_NAME, MAIN_ACTIVITY, PROXY_TARGET
    parser = argparse.ArgumentParser(description="Flutter TLS-bypass capture monitor")
    parser.add_argument("--package", required=True,
                        help="Target package name (e.g. com.example.app)")
    parser.add_argument("--process", default=None,
                        help="Target process name as shown by ps "
                             "(default: derived from --package)")
    parser.add_argument("--activity", default=None,
                        help="Launcher component (default: <package>/.MainActivity)")
    parser.add_argument("--once", action="store_true",
                        help="Run a single supervision cycle and exit")
    parser.add_argument("--port", type=int, default=FRIDA_PORT,
                        help=f"Frida remote port (default {FRIDA_PORT})")
    parser.add_argument("--interval", type=float, default=LOOP_INTERVAL,
                        help=f"Supervision loop interval seconds (default {LOOP_INTERVAL})")
    parser.add_argument("--proxy", default="",
                        help="Burp listener host:port for iptables DNAT "
                             "(used with --ensure-env)")
    parser.add_argument("--ensure-env", action="store_true",
                        help="Also re-assert iptables DNAT + system proxy")
    args = parser.parse_args()

    PACKAGE = args.package
    PROCESS_NAME = args.process or PACKAGE
    MAIN_ACTIVITY = args.activity or f"{PACKAGE}/.MainActivity"
    PROXY_TARGET = args.proxy
    FRIDA_PORT = args.port

    logger.info("Flutter capture monitor started (port=%s interval=%ss)",
                FRIDA_PORT, args.interval)

    if args.ensure_env:
        ensure_env()

    if args.once:
        ok = cycle(once=True)
        logger.info("Healthy: %s", ok)
        return 0 if ok else 1

    while True:
        try:
            cycle()
        except Exception as exc:  # pragma: no cover - watchdog
            logger.error("Cycle error: %s", exc)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())