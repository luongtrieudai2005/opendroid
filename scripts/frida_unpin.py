#!/usr/bin/env python3
"""Bypass SSL certificate pinning on Android app using Frida.

Usage:
    python frida_unpin.py com.target.app
    python frida_unpin.py com.target.app --method objection
    python frida_unpin.py com.target.app --custom my_script.js
"""

import argparse
import os
import sys
import subprocess
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.android_tools import frida_list_devices, frida_list_processes


UNIVERSAL_UNPIN_JS = """\
// Universal SSL unpinning for Android
// Source: https://github.com/httptoolkit/frida-interception-and-unpinning
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.registerClass({
        name: 'com.example.TrustAllManager',
        implements: [javax.net.ssl.X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // SSLContext bypass
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(keyManagers, trustManagers, secureRandom) {
        var tm = [TrustManager.$new()];
        this.init.call(this, keyManagers, tm, secureRandom);
    };

    // OkHttp bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() { return; };
    } catch(e) {}

    // HttpURLConnection bypass
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            var AllHosts = Java.registerClass({
                name: 'com.example.AllHosts',
                implements: [javax.net.ssl.HostnameVerifier],
                methods: {
                    verify: function(hostname, session) { return true; }
                }
            });
            this.setDefaultHostnameVerifier(AllHosts.$new());
        };
    } catch(e) {}

    // WebView bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
        };
    } catch(e) {}

    // Xposed-based modules bypass
    try {
        var XposedHelper = Java.use('de.robv.android.xposed.XposedHelpers');
        XposedHelper.findAndHookMethod.overload('java.lang.String', 'java.lang.ClassLoader', 'java.lang.String', 'java.lang.Object[]').implementation = function() { return; };
    } catch(e) {}

    console.log('[+] SSL pinning bypassed');
});
"""


def main():
    parser = argparse.ArgumentParser(
        description="Bypass SSL certificate pinning on Android"
    )
    parser.add_argument("package", help="Android package name (e.g., com.target.app)")
    parser.add_argument("--method", choices=["frida", "objection"], default="frida",
                       help="Bypass method (default: frida)")
    parser.add_argument("--custom", help="Path to custom Frida script")
    parser.add_argument("--device", default="usb",
                       help="Frida device: usb, local, or IP (default: usb)")
    parser.add_argument("--list-devices", action="store_true",
                       help="List connected Frida devices and exit")
    parser.add_argument("--list-processes", action="store_true",
                       help="List running processes and exit")
    args = parser.parse_args()

    if args.list_devices:
        devices = frida_list_devices()
        for d in devices:
            print(d)
        return

    if args.list_processes:
        processes = frida_list_processes(args.device)
        for p in processes:
            print(p)
        return

    print("=" * 55)
    print(f"  BYPASS SSL PINNING: {args.package}")
    print("=" * 55)

    if args.method == "objection":
        print("\n[*] Using objection...")
        cmd = [
            "objection", "-g", args.package, "explore",
            "-c", "android sslpinning disable",
            "--quiet"
        ]
        print(f"  $ {' '.join(cmd)}")
        subprocess.run(cmd)
        return

    # Frida method
    if args.custom:
        script_path = args.custom
        print(f"\n[*] Using custom Frida script: {script_path}")
    else:
        # Use built-in universal unpin script
        script_dir = Path(tempfile.gettempdir()) / "frida-scripts"
        script_dir.mkdir(parents=True, exist_ok=True)
        script_path = script_dir / "universal-unpin.js"
        if not script_path.exists():
            script_path.write_text(UNIVERSAL_UNPIN_JS)
            print(f"\n[*] Created universal unpin script at {script_path}")
        else:
            print(f"\n[*] Using existing script at {script_path}")

    device_arg = "-U" if args.device == "usb" else "-D"
    cmd = [
        "frida", device_arg, args.device if args.device != "usb" else "",
        "-f", args.package,
        "-l", str(script_path),
        "--no-pause",
        "-o", f"frida_{args.package}.log"
    ]
    cmd = [c for c in cmd if c]  # Remove empty strings

    print(f"\n[*] Running Frida...")
    print(f"  $ {' '.join(cmd)}")
    print(f"\n[*] App '{args.package}' will launch with SSL pinning disabled.")
    print("[*] All HTTPS traffic can now be intercepted by BurpSuite.")
    print("[*] Output logged to: frida_{args.package}.log")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        subprocess.run(cmd, timeout=300)
    except subprocess.TimeoutExpired:
        print("\n[!] Frida timed out after 5 minutes.")
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    except FileNotFoundError:
        print("\nERROR: frida not found in PATH.")
        print("  Install: pip install frida-tools")
        print("  Also push frida-server to device:")
        print("    adb root")
        print("    adb push frida-server-<version>-android-<arch> /data/local/tmp/")
        print("    adb shell chmod 755 /data/local/tmp/frida-server-*")
        print("    adb shell /data/local/tmp/frida-server-* &")
        sys.exit(1)


if __name__ == "__main__":
    main()
