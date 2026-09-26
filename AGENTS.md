# AGENTS.md — Hướng dẫn cho LLM phát triển dự án

## Thông tin môi trường
- OS: Windows
- Python: 3.13.1
- Package manager: pip
- Shell: PowerShell 5.1 (dùng `python script.py` để chạy)
- Code style: PEP8, type hints, docstrings
- Dependencies trong `requirements.txt`

## BurpSuite MCP
- MCP server: `http://127.0.0.1:9876` (SSE transport)
- Giao tiếp qua **curl.exe subprocess** (thư viện `requests` không compatible với SSE)
- File chính: `burp_mcp/client.py`
- **Bug hiện tại**: client.py cũ dùng 2 session riêng cho SSE listener và POST requests. Đã fix: SSE listener tự capture sessionId từ `endpoint` event.

## Project Structure (đã cập nhật)
- `burp_mcp/`: Core library, MCP client (đã fix SSE bug)
- `tools/http_tools.py`: HTTP request builder, parser, send_http (Burp hoặc direct)
- `tools/analysis.py`: Response analysis — SQL/XSS/info disclosure/debug/CORS/stacktrace
- `tools/intercept.py`: InterceptSession (Burp toggle) + MitmproxyController (full control)
- `tools/recon.py`: WSL2 bridge — subfinder, httpx, nuclei, ffuf, katana, gau qua `wsl.exe`
- `tools/fuzzing.py`: Parameter fuzzing engine (GET/POST/path/header) + wordlist loader
- `tools/android_tools.py`: adb, jadx, Frida wrappers
- `tools/apk_analyzer.py`: Full APK analysis pipeline + Firebase/AWS checker
- `tools/osint_tools.py`: Infrastructure OSINT — GitHub dorking, crt.sh, Shodan, tech intel
- `tools/business_logic.py`: Ride-hailing business logic — fare, GPS, promo, referral, race, OTP
- `tools/storage.py`: StorageManager — global SQLite + FTS5 + filesystem workspace
- `tools/workflow.py`: WorkflowEngine — YAML pipeline executor + ToolRegistry + variable resolver + pipe transforms
- `tools/workflow_tools.py`: 38 workflow tools (Phase 0 → 8) with @tool_meta
- `tools/mobsf_integration.py`: MobSF REST API client (upload, scan, diff)
- `tools/android_intent_tools.py`: Intent redirection, deep link fuzzer, component fuzzer, Content Provider scanner
- `tools/api_scanner.py`: GraphQL scanner, IDOR/BOLA tester, param tamper, JWT analyzer
- `tools/frida_manager.py`: Frida script management, template engine, auto-hook generation
- `tools/dynamic_sandbox.py`: Dynamic analysis sandbox — DB/pref/log dump via ADB
- `tools/flutter_tools.py`: Flutter app pentest — detect, reFlutter patch, Blutter WSL2 bridge, TLS bypass
- `workflows/default.yaml`: 9-phase Android pentest workflow (40 steps, includes Phase 0)
- `workflows/default_tier_a.yaml`: 7-phase workflow for mature targets (Grab-like, 37 steps)
- `workflows/android-bug-bounty-recon-workflow.md`: Recon workflow design doc (v2)
- `scripts/`: Demo + Android setup scripts
- `mcp_server/server.py`: FastMCP instance, lifespan (Burp connect/disconnect)
- `mcp_server/tools_registry.py`: 29 MCP tools (+OSINT, +business logic)
- `mcp_server/__main__.py`: Run with `python -m mcp_server` (stdio, auto-started by opencode)
- `.opencode/skills/bug-bounty/SKILL.md`: opencode skill (v2.0.0, stdio transport)

## WSL2 Integration
- Ubuntu 26.04 WSL2 với Go tools (`/home/trieudai/go/bin/`)
- Tools: subfinder, httpx, nuclei, ffuf, katana, gau, bbscope
- Gọi qua `wsl.exe /home/trieudai/go/bin/<tool>` (dùng full path để tránh Windows PATH interop issues)
- `tools/recon.py` quản lý WSL2 subprocess

## AVD Config
- Emulator: `D:\Applications\AndroidSDK\emulator\emulator.exe`
- AVD name: `opendroid` (API 36, x86_64, Google APIs - Android 16 Baklava)
- AVD path: `D:\IntelliJ\Android\.android\avd\opendroid.avd`
- Start: `emulator.exe -avd opendroid -writable-system -no-snapshot -memory 4096`
- adb root: `adb -s emulator-5554 root`
- Proxy: `adb -s emulator-5554 shell settings put global http_proxy 10.0.2.2:8080`
- Frida port: 27043 (27042 bị Windows reserved) → dùng `-H 127.0.0.1:27043`
- Frida server push: `adb push config/frida-server /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/frida-server`
- Frida server start: `adb shell /data/local/tmp/frida-server -D -l 0.0.0.0:27043 &`
- Frida forward: `adb forward tcp:27043 tcp:27043`

## Flutter Tools
- `tools/flutter_tools.py`: detect APK is Flutter, reFlutter patch, Blutter (WSL2/Docker), TLS bypass
- reFlutter: `pip install reflutter`
- Blutter (WSL2): `git clone https://github.com/worawit/blutter` vào WSL2 (`/home/trieudai/go/bin/`)
- Blutter (Docker): chạy container không cần WSL2
  ```powershell
  docker run --rm -v D:\path\to\lib\arm64-v8a:/data -v D:\path\to\output:/output blutter /data /output 2>&1
  ```
  - Mount thư mục chứa libflutter.so + libapp.so vào `/data`
  - Mount output dir vào `/output`
  - File output: pp.txt, objs.txt, blutter_frida.js, asm/
- Gọi trong code: `flutter_blutter_analyze(lib_dir=..., method="docker")`
- NVISO TLS bypass script trong `config/frida-scripts/flutter/disable_flutter_tls.js`
- Flutter workflow (Phase 2.5) tự động chạy nếu APK là Flutter app

## Test commands
```powershell
python -m mcp_server --sse                  # Start MCP server (SSE mode, port 9878)
python scripts/demo_full.py                # Test Burp MCP connection
python scripts/setup_emulator.py           # Setup Android emulator proxy + cert
python scripts/frida_unpin.py              # Bypass certificate pinning
python -c "from tools.recon import ensure_tools; print(ensure_tools())"  # Check WSL tools
python -c "from tools.workflow import WorkflowEngine; e=WorkflowEngine.__new__(WorkflowEngine); e.load('workflows/default.yaml'); print('OK')"  # Validate workflow
python -c "from tools.workflow import WorkflowEngine; e=WorkflowEngine.__new__(WorkflowEngine); e.load('workflows/default_tier_a.yaml'); print('OK')"  # Validate Tier A workflow
python -c "from tools.storage import StorageManager; s=StorageManager('workspace').init(); print(s.get_all_summary())"  # Storage summary
python -c "from tools.workflow_tools import program_intelligence; r=program_intelligence(policy_text='test', package_name='com.x'); print(r['tier'])"  # Phase 0 test
python -c "from tools.osint_tools import tech_intel; r=tech_intel(company_name='Grab'); print(len(r['services']))"  # OSINT test
python -c "from tools.business_logic import fare_check; r=fare_check(); print(r['count'])"  # Business logic test
```

## Android Pentesting
- Emulator proxy: `adb shell settings put global http_proxy 10.0.2.2:8080`
- Cert pinning bypass: `frida -U -f com.target.app -l universal-unpin.js`
- Decompile APK: `jadx -d output/ target.apk`
- Target device IP (emulator -> host): `10.0.2.2`
- Cần Burp CA cert cài trên device để intercept HTTPS
- Android workflow: decompile -> extract endpoints -> bypass pinning -> intercept via Burp MCP -> fuzz

## Lưu ý quan trọng
1. ĐANG OUT SCOPE ANDROID ATTACK SURFACE
2. `get_active_editor_contents` cần UI focus -> workaround: toggle intercept on/off
3. `send_to_intruder` có bug duplicate Host header -> dùng `send_http1_request` thay thế
4. Pro-only tools (scanner, collaborator) không dùng được
5. MCP response bị truncate 5000 chars -> parse cẩn thận
6. Integer params phải gửi dạng số nguyên (không phải float)
7. Dùng `curl.exe -s -N` cho SSE, `curl.exe -s --max-time X -X POST` cho request
8. Luôn match MCP response bằng message `id`
9. Gradle folder : D:\.gradle

## Code conventions
- Dùng `subprocess.Popen` cho SSE listener (background thread)
- Dùng `subprocess.run` cho POST request
- Thread riêng cho SSE reader, lock cho response dict
- Type hints cho mọi function
- Docstrings (Google style)
