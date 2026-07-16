---
name: bug-bounty
description: Bug bounty automation via BurpSuite MCP + AI recon tools. Use when user asks about intercepting, sending requests, recon, fuzzing, APK analysis, vulnerability assessment, or Android pentest.
---

# Bug Bounty Hunter

Use `bug-bounty-mcp` tools for Android pentest and web bug bounty.
Server runs via stdio (auto-started by opencode from `opencode.jsonc`).
BurpSuite + WSL2 Go tools (subfinder, httpx, nuclei) integrated.

## Startup

The MCP server starts automatically with opencode (stdio transport).
No manual server process needed.

For standalone SSE debugging:
```powershell
python -m mcp_server --sse      # Starts on http://0.0.0.0:9878/sse
```

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
| **MobSF** | `mobsf_analyze_endpoint` | Full MobSF APK static analysis (OWASP MASVS, malware, CVEs) |
| | `mobsf_check` | Check MobSF server availability |
| | `mobsf_apk_diff` | Compare two APK versions for new endpoints / removed security |
| **Intent** | `analyze_deep_links` | Extract deep links + fuzz URIs for token leak / auth bypass |
| | `find_intent_redirection` | Find intent forwarding without validation |
| | `fuzz_exported_components` | Fuzz exported components via ADB (malformed intents) |
| | `scan_content_providers` | Scan for Content Provider path traversal / SQL injection |
| **Flutter** | `flutter_detect` | Detect Flutter app + engine version |
| | `flutter_reflutter` | Patch APK with reFlutter for traffic intercept |
| | `flutter_pull_parse_dump` | Pull + parse reFlutter dump.dart (classes, functions) |
| | `flutter_blutter` | Run Blutter via WSL2 on libapp.so |
| | `flutter_parse_pp` | Parse Blutter pp.txt → URLs, secrets, classes |
| | `flutter_tls_bypass` | Bypass Flutter TLS (NVISO Frida script) |
| | `flutter_full_scan` | Full pipeline: detect → blutter → reflutter → bypass |
| **API** | `graphql_scan` | GraphQL introspection, auth bypass, batch abuse |
| | `idor_test` | IDOR/BOLA test with token swap on parameterised endpoints |
| | `jwt_scan` | Analyze JWT tokens (alg=none, weak secret, sensitive data) |
| **Sandbox** | `sandbox_dump_all` | Full dynamic dump: DBs + prefs + logs + screenshot |
| | `sandbox_analyze_db` | Analyze SQLite for sensitive data |
| **Frida** | `frida_list_scripts_tool` | List Frida scripts by category |
| | `frida_generate_hook` | Generate hook script from template + params |
| | `frida_run_script_tool` | Run Frida script (spawn/attach mode) |
| | `frida_bypass_all_tool` | Combined: SSL unpin + root bypass + proxy force |
| | `frida_combine_scripts_tool` | Combine multiple scripts into one |
| | `frida_auto_hook_tool` | Auto-generate hooks from decompiled classes |
| | `frida_list_templates_tool` | List available hook templates |
| | `frida_check_env_tool` | Check Frida environment readiness |

## Android Pentest Pipeline (8 phases)

Run: `workflow_run(apk_path="target.apk", package_name="com.target.app")`

1. **Recon & Preparation** — APK import, env check, tech intel
2. **Static Analysis** — Decompile, manifest, endpoints, secrets, native libs, Firebase, **MobSF deep analysis**, **Content Provider scan**, **Flutter detect**
3. **Flutter Analysis** (auto if Flutter app) — **Blutter** (pp.txt parsing), **reFlutter** patch, **TLS bypass**
3. **IPC & Component Testing** — Exported components, deep links, intents, **intent redirection**, **deep link fuzzing**, **component fuzzing**
4. **Dynamic + Network Analysis** — SSL bypass, proxy, traffic capture, API discovery, **Frida bypass_all**, **Frida auto-hooks**
5. **Local Storage** — SharedPreferences, SQLite, files, keystore, **Dynamic Sandbox** (DB+prefs+logs dump)
6. **Backend API Testing** — Subdomains, httpx, nuclei, fuzz, auth, **GraphQL scan**, **IDOR/BOLA test**, **param tamper**, **JWT analysis**
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
