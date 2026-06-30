# opendroid

**AI-powered Android pentest automation: opencode LLM agent + Burp Suite + WSL2 recon + full workflow engine. APK → static/dynamic analysis → 0-day.**

---

## What is this?

**opendroid** turns opencode into a specialized Android penetration testing agent. It combines:

- **LLM reasoning** (via opencode) to plan, adapt, and analyze findings
- **Burp Suite MCP** for live traffic interception, repeater, and proxy history
- **WSL2 native tools** (subfinder, httpx, nuclei, katana, gau, ffuf) for recon at scale
- **Frida/jadx/adb** for dynamic instrumentation, decompilation, and device control
- **Workflow engine** (YAML, 8 phases, 35 steps) with variable resolution, foreach loops, and pipe transforms
- **Global SQLite + FTS5 storage** for cross-target search, multi-APK versioning, and report generation
- **Skill system** (`.opencode/skills/bug-bounty`) for reusable pentest patterns

---

## Quick Start

```bash
# 1. Start Burp Suite + MCP extension (port 9876)
# 2. Start Python MCP server (port 9878)
python -m mcp_server

# 3. In opencode, connect to bug-bounty-mcp
# 4. Run full Android pentest workflow
workflow_run(apk_path="target.apk", package_name="com.target.app")
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        opencode (LLM Agent)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │ MCP (SSE)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Python MCP Server (9878)                     │
│  ┌──────────┬──────────┬──────────┬──────────┬────────────────┐ │
│  │ Burp MCP │  Recon   │ Fuzzing  │ Android  │   Storage      │ │
│  │  Tools   │ (WSL2)   │ Engine   │  Tools   │  (SQLite+FTS5) │ │
│  └──────────┴──────────┴──────────┴──────────┴────────────────┘ │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   ┌─────────┐         ┌───────────┐        ┌──────────┐
   │ Burp    │         │  WSL2     │        │ Android  │
   │ Suite   │         │ (subfinder│        │ (adb,    │
   │ MCP     │         │  httpx,   │        │  frida,  │
   │ (9876)  │         │  nuclei...)│        │  jadx)   │
   └─────────┘         └───────────┘        └──────────┘
```

---

## Features

### Burp Suite Integration (via MCP)
- Send HTTP/1.1 & HTTP/2 requests through Burp
- Read proxy history with regex filtering
- Control intercept state (enable/disable/status)
- Create Repeater/Intruder tabs programmatically

### Reconnaissance Pipeline (WSL2)
- **subfinder** — passive subdomain enumeration
- **httpx** — live host probing + tech detection
- **nuclei** — template-based vulnerability scanning
- **katana** — crawler for endpoint discovery
- **gau** — Wayback Machine URL collection
- **ffuf** — directory/parameter fuzzing
- **bbscope** — bug bounty scope validation

### Android Pentest Toolkit
- **jadx** — APK decompilation
- **Frida** — dynamic instrumentation, SSL pinning bypass
- **adb** — device control, proxy setup, data extraction
- **objection** — mobile exploration framework

### Workflow Engine
- YAML-defined pipelines (8 phases, 35 steps)
- Variable resolution: `{step.field}`, `{list | map(.url) | unique}`
- Pipe transforms: `length`, `unique`, `map`, `filter`, `extract_domains`
- Conditional execution: `when`, `on_fail` (stop/skip/continue)
- Foreach loops over lists

### Storage & Reporting
- Global SQLite database with FTS5 full-text search
- Multi-APK per target (versions, debug/release, AAB splits)
- Categorized endpoints (external, internal, cloud, third-party, CDN)
- Cross-target search across endpoints, secrets, findings
- Markdown/JSON report generation

---

## Project Structure

```
opendroid/
├── README.md
├── AGENTS.md              # LLM development guide
├── requirements.txt
├── opencode.jsonc         # opencode MCP config
├── .opencode/skills/bug-bounty/SKILL.md
│
├── burp_mcp/              # Core Burp MCP client (SSE fixed)
│   └── client.py
│
├── tools/                 # Tool implementations
│   ├── http_tools.py      # HTTP request builder/parser
│   ├── analysis.py        # Response vulnerability analysis
│   ├── intercept.py       # Burp intercept + mitmproxy controller
│   ├── recon.py           # WSL2 bridge (subfinder, httpx, nuclei...)
│   ├── fuzzing.py         # Parameter fuzzing engine
│   ├── android_tools.py   # adb, jadx, Frida wrappers
│   ├── apk_analyzer.py    # Full APK analysis pipeline
│   ├── osint_tools.py     # GitHub dorking, crt.sh, Shodan, tech intel
│   ├── business_logic.py  # Ride-hailing logic (fare, GPS, promo, OTP)
│   ├── storage.py         # SQLite + FTS5 workspace manager
│   ├── workflow.py        # YAML workflow engine
│   └── workflow_tools.py  # 38 @tool_meta workflow tools (Phase 0→8)
│
├── workflows/
│   ├── default.yaml       # 9-phase Android pentest workflow (Phase 0)
│   ├── default_tier_a.yaml# 7-phase workflow for mature targets
│   └── android-bug-bounty-recon-workflow.md  # Design doc v2
│
├── mcp_server/            # Python MCP server (port 9878)
│   ├── server.py          # FastMCP + lifespan
│   ├── tools_registry.py  # 29 MCP tools (incl. OSINT + business logic)
│   └── __main__.py
│
├── config/
│   └── wordlists/         # xss.txt, sqli.txt, dirs.txt, params.txt
│
├── scripts/               # Demo & setup scripts
│   ├── demo_full.py
│   ├── setup_emulator.py
│   └── frida_unpin.py
│
└── workspace/             # SQLite DB + per-target files (gitignored)
```

---

## Requirements

| Tool | Purpose | Install |
|------|---------|---------|
| **Python** | ≥3.11 | `winget install Python.Python.3.13` |
| **Burp Suite Pro** | MCP extension runs here | PortSwigger |
| **opencode** | LLM agent | `npm i -g @opencode-ai/opencode` |
| **WSL2 Ubuntu** | Linux recon tools | `wsl --install` |
| **Go tools in WSL2** | subfinder, httpx, nuclei, ffuf, katana, gau, bbscope | `go install ...` |
| **jadx** | APK decompilation | `winget install jadx` |
| **Frida** | Dynamic instrumentation | `pip install frida-tools` |
| **adb** | Android device control | Android SDK Platform Tools |
| **mitmproxy** (optional) | Full HTTP control | `pip install mitmproxy` |

---

## MCP Server Tools (29)

| Category | Tools |
|----------|-------|
| **Burp** | `burp_connect`, `burp_status`, `burp_list_tools`, `send_http_request`, `proxy_history`, `intercept` |
| **Analysis** | `analyze_http_response`, `analyze_last_request` |
| **Recon** | `recon_check_tools`, `recon_subdomains`, `run_full_recon_pipeline`, `run_nuclei_scan` |
| **Fuzzing** | `fuzz_parameter`, `fuzz_url_path` |
| **Android** | `android_list_packages`, `android_proxy`, `bypass_ssl_pinning`, `decompile_android_apk` |
| **OSINT** | `github_search`, `crtsh_search`, `shodan_infra`, `tech_intel_gather` (new) |
| **Business Logic** | `fare_manipulation_test`, `gps_spoof_test` (new) |
| **Workflow** | `workflow_run`, `workflow_list`, `workflow_status` |
| **Storage** | `storage_summary`, `generate_vulnerability_report` |

---

## Workflow: 8 Phases

1. **Recon & Preparation** — APK import, env check
2. **Static Analysis** — jadx decompile, manifest, endpoints, secrets, obfuscation, native libs, Firebase check
3. **IPC & Component Testing** — exported components, deep links, intent analysis
4. **Dynamic + Network** — SSL pinning bypass, root bypass, proxy setup, traffic capture, API discovery, WebSocket check
5. **Local Storage** — SharedPreferences, SQLite, filesystem, Keystore
6. **Backend API** — subdomain enum, httpx, nuclei, API fuzzing, auth testing
7. **Advanced** — WebView, JS interface, crypto, backup testing
8. **Reporting** — markdown report generation

Run: `workflow_run(apk_path="app.apk", package_name="com.target.app")`

---

## License

MIT — Use responsibly. Only test systems you own or have explicit permission to test.