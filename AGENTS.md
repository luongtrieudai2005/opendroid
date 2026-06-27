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
- `tools/storage.py`: StorageManager — global SQLite + FTS5 + filesystem workspace
- `tools/workflow.py`: WorkflowEngine — YAML pipeline executor + ToolRegistry + variable resolver + pipe transforms
- `workflows/default.yaml`: 8-phase Android pentest workflow (35 steps)
- `scripts/`: Demo + Android setup scripts
- `mcp_server/server.py`: FastMCP instance, lifespan (Burp connect/disconnect)
- `mcp_server/tools_registry.py`: 23 MCP tools (burp, analysis, recon, fuzzing, android, workflow, storage)
- `mcp_server/__main__.py`: Run with `python -m mcp_server` (port 9878, SSE)
- `.opencode/skills/bug-bounty/SKILL.md`: opencode skill (v2.0.0, MCP port 9878)

## WSL2 Integration
- Ubuntu 26.04 WSL2 với Go tools (`/home/trieudai/go/bin/`)
- Tools: subfinder, httpx, nuclei, ffuf, katana, gau, bbscope
- Gọi qua `wsl.exe /home/trieudai/go/bin/<tool>` (dùng full path để tránh Windows PATH interop issues)
- `tools/recon.py` quản lý WSL2 subprocess

## Test commands
```powershell
python -m mcp_server                       # Start MCP server on port 9878
python scripts/demo_full.py                # Test Burp MCP connection
python scripts/setup_emulator.py           # Setup Android emulator proxy + cert
python scripts/frida_unpin.py              # Bypass certificate pinning
python -c "from tools.recon import ensure_tools; print(ensure_tools())"  # Check WSL tools
python -c "from tools.workflow import WorkflowEngine; e=WorkflowEngine.__new__(WorkflowEngine); e.load('workflows/default.yaml'); print('OK')"  # Validate workflow
python -c "from tools.storage import StorageManager; s=StorageManager('workspace').init(); print(s.storage_summary())"  # Storage summary
```

## Android Pentesting
- Emulator proxy: `adb shell settings put global http_proxy 10.0.2.2:8080`
- Cert pinning bypass: `frida -U -f com.target.app -l universal-unpin.js`
- Decompile APK: `jadx -d output/ target.apk`
- Target device IP (emulator -> host): `10.0.2.2`
- Cần Burp CA cert cài trên device để intercept HTTPS
- Android workflow: decompile -> extract endpoints -> bypass pinning -> intercept via Burp MCP -> fuzz

## Lưu ý quan trọng
1. **KHÔNG dùng Java/Gradle** (user không muốn)
2. `get_active_editor_contents` cần UI focus -> workaround: toggle intercept on/off
3. `send_to_intruder` có bug duplicate Host header -> dùng `send_http1_request` thay thế
4. Pro-only tools (scanner, collaborator) không dùng được
5. MCP response bị truncate 5000 chars -> parse cẩn thận
6. Integer params phải gửi dạng số nguyên (không phải float)
7. Dùng `curl.exe -s -N` cho SSE, `curl.exe -s --max-time X -X POST` cho request
8. Luôn match MCP response bằng message `id`

## Code conventions
- Dùng `subprocess.Popen` cho SSE listener (background thread)
- Dùng `subprocess.run` cho POST request
- Thread riêng cho SSE reader, lock cho response dict
- Type hints cho mọi function
- Docstrings (Google style)
