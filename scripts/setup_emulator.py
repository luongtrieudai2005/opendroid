#!/usr/bin/env python3
"""Setup Android emulator for BurpSuite interception.

Steps:
1. Set HTTP proxy on emulator to point to host (10.0.2.2:8080)
2. Install Burp CA certificate on emulator
3. Verify setup
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Add project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.android_tools import run_adb, set_proxy, remove_proxy


def check_adb() -> bool:
    """Check adb is available and device is connected."""
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        devices = [l for l in lines if l and "\tdevice" in l]
        if not devices:
            print("ERROR: No Android device/emulator connected.")
            print("  Start emulator and run: adb devices")
            return False
        print(f"  Device: {devices[0].split()[0]}")
        return True
    except FileNotFoundError:
        print("ERROR: adb not found in PATH.")
        print("  Install Android SDK Platform Tools")
        return False
    except subprocess.TimeoutExpired:
        print("ERROR: adb command timed out.")
        return False


def check_burp_cert() -> Path | None:
    """Find Burp CA certificate in common locations."""
    candidates = [
        Path.home() / ".BurpSuite" / "burpca.der",
        Path.home() / "Desktop" / "cacert.der",
        Path.home() / "Downloads" / "cacert.der",
        Path.home() / "AppData" / "Roaming" / "BurpSuite" / "burpca.der",
        Path("cacert.der"),
        Path("burpca.der"),
    ]
    for p in candidates:
        if p.exists():
            print(f"  Found Burp CA cert at: {p}")
            return p

    # Try to export from Burp via MCP (if Burp is running)
    print("  Burp CA cert not found in common locations.")
    print("  Export manually: Burp -> Proxy -> Options -> Import/Export CA cert")
    print("  Or place cacert.der in this directory.")
    return None


def install_cert_on_device(cert_path: Path) -> bool:
    """Install Burp CA certificate on Android emulator."""
    print("\n[3] Installing Burp CA certificate on device...")

    # Get device API level
    result = run_adb(["shell", "getprop", "ro.build.version.sdk"])
    api_level = int(result.stdout.strip() or "0")
    print(f"  Android API level: {api_level}")

    # For Android 14+, user certificates can be installed directly
    if api_level >= 34:
        print("  Android 14+: Installing as user certificate")
        remote = "/sdcard/Download/cacert.der"
        run_adb(["push", str(cert_path), remote])
        print(f"  Pushed cert to {remote}")
        print("  Install manually: Settings -> Security -> Credentials -> Install")
        print("  Select the file from /sdcard/Download/")
        return False

    # For Android <14: install as system certificate (requires root)
    try:
        # Push and install
        run_adb(["root"], timeout=5)
        run_adb(["remount"], timeout=5)

        # Calculate hash
        import hashlib
        cert_data = cert_path.read_bytes()
        # Subject hash for Android
        # We use openssl to calculate proper hash
        result = subprocess.run(
            ["openssl", "x509", "-inform", "der", "-in", str(cert_path),
             "-subject_hash_old", "-noout"],
            capture_output=True, text=True, timeout=10
        )
        cert_hash = result.stdout.strip()

        converted = Path(tempfile.gettempdir()) / f"{cert_hash}.0"
        subprocess.run(
            ["openssl", "x509", "-inform", "der", "-in", str(cert_path),
             "-outform", "der", "-out", str(converted)],
            capture_output=True, timeout=10
        )

        # Push to system cert store
        run_adb(["push", str(converted), f"/system/etc/security/cacerts/{cert_hash}.0"],
                timeout=10)
        run_adb(["shell", "chmod", "644", f"/system/etc/security/cacerts/{cert_hash}.0"],
                timeout=5)

        print(f"  Certificate installed as system CA: {cert_hash}.0")
        print("  Rebooting device...")
        run_adb(["reboot"], timeout=5)
        return True

    except Exception as e:
        print(f"  WARNING: Could not install system cert: {e}")
        print("  Alternative: Install as user cert (manual)")
        run_adb(["push", str(cert_path), "/sdcard/Download/cacert.der"])
        print("  Pushed to /sdcard/Download/. Install manually via Settings.")
        return False


def test_connection() -> bool:
    """Test that interception works by sending a request."""
    print("\n[4] Testing proxy connection...")
    try:
        import requests
        proxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        r = requests.get("https://httpbin.org/get", proxies=proxy, timeout=10)
        print(f"  SUCCESS: Connected through Burp proxy (status={r.status_code})")
        return True
    except ImportError:
        print("  SKIP: requests library not installed")
        return False
    except Exception as e:
        print(f"  FAILED: {type(e).__name__}: {e}")
        print("  Make sure BurpSuite is running and proxy is on port 8080")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Setup Android emulator for BurpSuite interception"
    )
    parser.add_argument("--cert", help="Path to Burp CA certificate (.der)")
    parser.add_argument("--port", type=int, default=8080,
                       help="Burp proxy port (default: 8080)")
    parser.add_argument("--remove", action="store_true",
                       help="Remove proxy settings instead of adding")
    parser.add_argument("--only-proxy", action="store_true",
                       help="Only set proxy, skip certificate")
    args = parser.parse_args()

    print("=" * 55)
    print("  ANDROID EMULATOR SETUP FOR BURPSUITE")
    print("=" * 55)

    # Check adb
    print("\n[1] Checking adb connection...")
    if not check_adb():
        sys.exit(1)

    if args.remove:
        print("\n[2] Removing proxy...")
        remove_proxy()
        print("  Done.")
        return

    # Set proxy
    print(f"\n[2] Setting proxy to 10.0.2.2:{args.port}...")
    set_proxy(port=args.port)
    print("  Proxy configured.")

    if args.only_proxy:
        print("\n  Done. Proxy set. Install certificate manually if needed.")
        return

    # Find and install cert
    if args.cert:
        cert_path = Path(args.cert)
    else:
        cert_path = check_burp_cert()

    if cert_path and cert_path.exists():
        install_cert_on_device(cert_path)
    else:
        print("\n[3] SKIP: No Burp CA certificate found.")
        print("  Export from Burp: Proxy -> Options -> CA Certificate -> Export")

    # Test
    test_connection()

    print("\n" + "=" * 55)
    print("  SETUP COMPLETE")
    print("=" * 55)
    print("  Proxy: 10.0.2.2:8080")
    print("  Start app on emulator -> traffic should appear in Burp")
    print("  To remove proxy: python setup_emulator.py --remove")


if __name__ == "__main__":
    main()
