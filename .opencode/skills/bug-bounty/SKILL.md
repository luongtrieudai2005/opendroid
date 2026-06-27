---
name: bug-bounty
description: Bug bounty automation via BurpSuite MCP + AI recon tools. Use when user asks about intercepting, sending requests, recon, fuzzing, APK analysis, vulnerability assessment, or Android pentest.
---

# Bug Bounty Hunter

Use the MCP tools at port 9878 for Android pentest and web bug bounty.
BurpSuite + WSL2 Go tools (subfinder, httpx, nuclei) integrated.

## Available MCP Tools

| Category | Tool | Description |
|----------|------|-------------|
| **Burp** | `send_http_request` | Send HTTP request through Burp |
| | `proxy_history` | Read Burp proxy HTTP history |
| | `intercept` | Toggle Burp intercept on/off |
| | `burp_connect` / `burp_status` | Test/check Burp connection |
| **Analysis** | `analyze_http_response` | Detect SQLi, XSS, info disclosure, CORS, etc. |
| | `analyze_last_request` | Analyze recent proxy entries |
| **Recon** | `recon_subdomains` | Subdomain discovery via subfinder (WSL2) |
| | `run_nuclei_scan` | Vulnerability scanning via nuclei |
| | `run_full_recon_pipeline` | Full recon: subfinder → httpx → nuclei |
| **Fuzzing** | `fuzz_parameter` | Fuzz GET/POST params with XSS/SQLi payloads |
| | `fuzz_url_path` | Fuzz URL paths with directory wordlist |
| **Android** | `decompile_android_apk` | Decompile APK, extract endpoints + secrets |
| | `android_list_packages` | List installed packages on device |
| | `android_proxy` | Set/remove emulator proxy |
| | `bypass_ssl_pinning` | Bypass SSL pinning with Frida |
| **Workflow** | `workflow_run` | Execute full 8-phase Android pentest pipeline |
| | `workflow_list` | List available workflow definitions |
| | `workflow_status` | Check workflow execution results |
| **Storage** | `storage_summary` | Workspace overview across all targets |
| **Report** | `generate_vulnerability_report` | Generate markdown report |

## Android Pentest Pipeline (8 phases)

Run: `workflow_run(apk_path="target.apk", package_name="com.target.app")`

1. **Recon & Preparation** — APK import, env check
2. **Static Analysis** — Decompile, manifest, endpoints, secrets, native libs, Firebase
3. **IPC & Component Testing** — Exported components, deep links, intents
4. **Dynamic + Network Analysis** — SSL bypass, proxy, traffic capture, API discovery
5. **Local Storage** — SharedPreferences, SQLite, files, keystore
6. **Backend API Testing** — Subdomains, httpx, nuclei, fuzz, auth
7. **Advanced Testing** — WebView, JS interfaces, crypto, backup
8. **Reporting** — Full markdown report

## Workflows

### Quick Android Test
```
workflow_run(apk_path="target.apk", package_name="com.target.app")
workflow_status(target_id=1)
```

### Intercept & Analyze
1. `intercept(action="enable")` to turn on Burp intercept
2. User performs action on device
3. `proxy_history(count=1)` to read captured request
4. `analyze_http_response(body="...")` to detect vulnerabilities

### Full Recon on Domain
1. `recon_subdomains(domain="example.com")`
2. `run_full_recon_pipeline(domain="example.com")`
3. Review findings from nuclei/httpx

### APK Analysis Only (no workflow)
1. `decompile_android_apk(apk_path="target.apk")`
2. Review extracted endpoints, secrets, Firebase URLs
