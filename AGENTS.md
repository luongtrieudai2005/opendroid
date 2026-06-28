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

## Test commands
```powershell
python -m mcp_server                       # Start MCP server on port 9878
python scripts/demo_full.py                # Test Burp MCP connection
python scripts/setup_emulator.py           # Setup Android emulator proxy + cert
python scripts/frida_unpin.py              # Bypass certificate pinning
python -c "from tools.recon import ensure_tools; print(ensure_tools())"  # Check WSL tools
python -c "from tools.workflow import WorkflowEngine; e=WorkflowEngine.__new__(WorkflowEngine); e.load('workflows/default.yaml'); print('OK')"  # Validate workflow
python -c "from tools.storage import StorageManager; s=StorageManager('workspace').init(); print(s.get_all_summary())"  # Storage summary
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

## Frida HTTP Hook (V6 — Working!)
- Hook `okhttp3.HttpUrl$Builder.build()` → captures URL construction
- Hook không gây crash app (không recursion)
- Script: `config/frida-scripts/bypass_pairip.js` (trong Pairip section)
- Lưu ý: OkHttp 4.x dùng Kotlin properties → `req.getUrl()` thay vì `req.url()`

## Pairip License Bypass (Working — V2: attach mode)

### ⚠️ CRITICAL: Java.perform() broken in `-f` spawn mode on Android 16
`Java.perform()` (async) does NOT fire its callback in `-f` spawn mode on Android 16 Baklava (SDK 36).
`setInterval`/`setTimeout` also do NOT fire. The Frida agent's event loop is effectively dead until the
main thread resumes, but by then Pairip has already run. `Java.performNow()` (sync) works but runs
before the app's PathClassLoader is set up → `Java.use()` sees empty `DexPathList[[directory "."]]`.

**Solution: attach mode with pm clear timing window.**

### Key Insight
1. `pm clear com.whatnot_mobile` removes Pairip's cached fail state from SharedPreferences
2. Without cache, Pairip contacts Google Play Licensing service on startup (takes 3-5s timeout, no Play Store on AVD)
3. Start app with monkey, attach Frida to PID within 1s
4. In attach mode, `Java.perform()` and `setTimeout` work correctly
5. Hooks intercept `checkLicense()` before the licensing callback returns
6. `licenseCheckState = LOCAL_CHECK_REPORTED` → `initializeLicenseCheck()` returns immediately
7. 5 layers of hooks prevent any error dialog

### Problem
- Pairip `com.pairip.licensecheck.LicenseClient` checks Google Play licensing on app startup
- AVD không có real Play Store → licensing service returns error → `handleError()` shows "Something went wrong" dialog
- Dialog blocks app usage entirely

### Solution: 5-Layer Hook + Attach Mode Timing

**Key classes** (`jadx` decompiled):
- `LicenseClient`: Main class with `checkLicense()` → `initializeLicenseCheck()` → `onServiceConnected()` → `checkLicenseInternal()` → `handleError()`
- `LicenseClient.LicenseCheckState`: Enum with values `CHECK_REQUIRED(0)`, `FULL_CHECK_OK(1)`, `LOCAL_CHECK_OK(2)`, `LOCAL_CHECK_REPORTED(3)`, `REPEATED_CHECK_REQUIRED(4)`
- `LicenseActivity`: UI activity showing error dialog / paywall

**Hook strategy** (5 layers):
1. **State preset**: `licenseCheckState = LOCAL_CHECK_REPORTED` (ordinal 3) — makes `initializeLicenseCheck()` return immediately without calling `validateResponse(null)` which would throw (CRITICAL: was using `FULL_CHECK_OK` but that causes `validateResponse(null)` → exception → `handleError`)
2. **checkLicense no-op**: Hook `checkLicense(Context)` → return immediately — prevents the entire license check flow
3. **handleError suppression**: Hook `handleError(LicenseCheckException)` → no-op — prevents `startErrorDialogActivity()` from being called
4. **startErrorDialogActivity + startPaywallActivity no-op**: Fallback hooks for error UI methods
5. **No Google Play hook needed** (attach mode timing makes it unnecessary)

### Script: `config/frida-scripts/bypass_pairip.js`

### Frida Command (PowerShell)
```powershell
# Step 1: Clear Pairip cache so it must contact Play Licensing (3-5s timeout window)
adb -s emulator-5554 shell "pm clear com.whatnot_mobile"

# Step 2: Start app
adb -s emulator-5554 shell "monkey -p com.whatnot_mobile 1"

# Step 3: Wait 1s for process creation, NOT more (Pairip licensing call ~3-5s)
Start-Sleep -Seconds 1

# Step 4: Get PID and attach Frida
$pid = $(adb -s emulator-5554 shell "ps -A | grep whatnot | head -1" 2>&1 | ForEach-Object { if ($_ -match '^\S+\s+(\d+)') { $matches[1] } })
frida -H 127.0.0.1:27043 -p $pid -l config/frida-scripts/bypass_pairip.js -q
```

### Why NOT spawn mode
```
-f spawn mode:     Java.perform() broken → hooks never fire → Pairip runs unhindered → dialog
monkey + attach:   Java.perform() works → hooks installed before Play Licensing returns → bypass
```

### Why `LOCAL_CHECK_REPORTED` instead of `FULL_CHECK_OK`:
```
FULL_CHECK_OK:
  initializeLicenseCheck() → validateResponse(responsePayload, pkg)
  → responsePayload is null (never set, only in processResponse callback)
  → LicenseCheckException → handleError() ← triggers dialog!

LOCAL_CHECK_REPORTED:
  initializeLicenseCheck() → ordinal==3 → "if (iOrdinal != 1)" → true
  → "if (iOrdinal != 4)" → true → return; ← exits cleanly!
```

## Critical Session Data (28 Jun 2026)
### JWT Token (Whatnot Access — EdDSA)
```
eyJhbGciOiJFZERTQSIsImtpZCI6IndoYXRub3QtYWNjZXNzLXByb2QtMyIsInR5cCI6IkpXVCJ9.eyJzdWIiOjY0ODIwODQ5LCJpc3MiOiJ3aGF0bm90L2F1dGgiLCJhdWQiOiJ3aGF0bm90L2FjY2VzcyIsImV4cCI6MTc4MjYxNzY4NSwiaWF0IjoxNzgyNjE3Mzg1LCJuYmYiOjE3ODI2MTczODUsImp0aSI6IkNsM3JqMC10Q3FwWU1FcFlXMFhwQXciLCJhcHBzaWQiOiIwYjc5M2IzMi0yZDA5LTQ3NDAtYjhmMi0wNjNkOGFiYTc5MDciLCJ1cHIiOjAuMiwiaWRlbnRpdHkiOiJsdW9uZzNnM2crd2hhdG5vdEB3ZWFyZWhhY2tlcm9uZS5jb20ifQ.qtbYOZ34D8WK1u3_Kgn_tFAuyaWzwiGyJ_hjEDXWexiTa3IRjzd1lfoPd6hqxlNO16Td9lbsfZC_ljl16D2PBg
```
- **User**: `luong3g3g+whatnot@wearehackerone.com` (Luong Trieu Dai, UID 64820849)
- **GraphQL Node ID**: `VXNlck5vZGU6NjQ4MjA4NDk=` (base64: `UserNode:64820849`)
- **Kid**: `whatnot-access-prod-3`, **Alg**: EdDSA (Ed25519)
- **Exp**: 1782617685 (~30 days), **UPR**: 0.2
- **App session ID**: `0b793b32-2d09-4740-b8f2-063d8aba7907`
- **JTI**: `Cl3rj0-tCqpYMEpYW0XpAw`

### Whatnot Infrastructure
| Service | URL |
|---------|-----|
| GraphQL | `POST https://api.whatnot.com/graphql/` |
| Live Service | `wss://live-service.whatnot.com/socket/websocket` |
| Auction | `https://auction-service.whatnot.com/` |
| Token Refresh | `POST https://api.whatnot.com/api/v2/refresh` |
| Events | `POST https://api.whatnot.com/events/v1/b` |
| Payment | `https://api.stripe.com/` (live acct `acct_1F9IrgEl9v5uEzcr`) |
| Firebase RTDB | `https://whatnot-cd964.firebaseio.com/` (401 locked) |
| Firebase Auth | `identitytoolkit.googleapis.com` (anonymous+password disabled) |
| Support | `https://whatnot.zendesk.com/sc/sdk/` |

### GraphQL Operations Discovered
`Me`, `GetAccountControlsAlarms`, `GetPaymentConfigurationQuery`, `HomeReactivationCheck_OnboardingUserState`, `RegisterUserDevice`

### User PII Accessible
```json
{"id":"VXNlck5vZGU6NjQ4MjA4NDk=","email":"luong3g3g+whatnot@wearehackerone.com",
 "displayName":"Luong Trieu Dai","phoneNumber":null,
 "createdAt":"Sat, 27 Jun 2026 14:51:48 GMT",
 "balance":{"amount":0,"currency":"USD"}}
```

### Firebase Keys
- **API Key**: `AIzaSyC9s9yLyArEVN7MEIdXBJ3xwVLmQcgo4FU` (Android-restricted)
- **FID**: `cloZXV7gS4qmIKoI3CpMRi`
- **Project**: `whatnot-cd964` (project #1047454820591)
- **OAuth Client ID**: `1047454820591-v9gb4g9aitt8ginthcom1loan201t8l0.apps.googleusercontent.com`

## Code conventions
- Dùng `subprocess.Popen` cho SSE listener (background thread)
- Dùng `subprocess.run` cho POST request
- Thread riêng cho SSE reader, lock cho response dict
- Type hints cho mọi function
- Docstrings (Google style)

## Current Session: Pairip Bypass + Restored (2026-06-28)

### Pairip Status
- **V2 method working** — attach mode + pm clear timing window
- Script: `config/frida-scripts/bypass_pairip.js`
- App running with `MainActivity` (no LicenseActivity)
- Ready for HTTP interception / GraphQL capture

### Frida User (App session)
- **User**: luong3g3g+whatnot@wearehackerone.com — Luong Trieu Dai
- **UID**: 64820849 (GraphQL: VXNlck5vZGU6NjQ4MjA4NDk=)
- **Balance**: $0 USD
- **Created**: 2026-06-27
- **AT**: EdDSA, kid=whatnot-access-prod-3, exp=1782617685, JTI=Cl3rj0-tCqpYMEpYW0XpAw
- **App session ID**: 0b793b32-2d09-4740-b8f2-063d8aba7907
- **RT captured**: Confirmed no rotation (old RT valid after refresh)

### Web User (Browser session) — CONFIRMED WORKING
- **User**: luongtrieudai0902@gmail.com — Đại Lương Triều
- **UID**: 64889310 (GraphQL: VXNlck5vZGU6NjQ4ODkzMTA=)
- **Phone**: +84927094519 ← PII critical!
- **Balance**: $0 USD
- **Created**: 2026-06-28 03:32:03 GMT
- **App session ID**: b7dba0bb-7d8a-47a3-ab67-332275222ae5
- **UPR**: 0.2

### Token Refresh Technique
- **Endpoint**: `POST https://api.whatnot.com/api/v2/refresh`
- **Format**: `Authorization: Bearer <RT>` (KHÔNG phải AT!) + body `{"refreshToken":"<RT>"}`
- **Response**: New AT (300s) + New RT (1 year) + same `appsid`
- **Rotation**: RT rotates (new `session_token` each refresh) but **same session** — `fp=none` allows cross-IP

### Web GraphQL
| Query | Status | Notes |
|-------|--------|-------|
| `Me` | ✅ Working | Full PII (email, phone, displayName, balance) |
| `SearchBarSuggestions` | ✅ Working | From browser |
| `getUser(id:)` | ❌ Not in schema | No `user` field on Query type |
| `node(id:)` | ❌ Returns null | For other users' IDs |
| `getPaymentConfiguration` | ❌ Mobile-only | Not on web schema |
| `getAccountControlsAlarms` | ❌ Mobile-only | Not on web schema |
| `homeReactivationCheck` | ❌ Mobile-only | Not on web schema |
| `__schema` / `__type` | ❌ Disabled | Introspection blocked |
| `RegisterUserDevice` | ❌ Mobile-only | Mutation not on web |

### Firebase Analysis
| Service | Status |
|---------|--------|
| RTDB (whatnot-cd964.firebaseio.com) | Exists, 401 (requires auth) |
| Firestore | 404 (not enabled) |
| Storage bucket | 404 (not found) |
| Remote Config | 403 (App Check — needs X-Android headers) |
| Auth anonymous | Disabled |
| Auth password | Disabled |

### Whatnot Infrastructure
| Service | Type |
|---------|------|
| api.whatnot.com/graphql/ | GraphQL (5 ops: Me, GetAccountControlsAlarms, GetPaymentConfigurationQuery, HomeReactivationCheck_OnboardingUserState, RegisterUserDevice) |
| api.whatnot.com/api/v2/refresh | Token refresh |
| api.whatnot.com/events/v1/b | Analytics |
| live-service.whatnot.com/socket/websocket | Phoenix WebSocket (JWT in URL) |
| auction-service.whatnot.com | Auction microservice |
| api.stripe.com/ | Stripe live (acct_1F9IrgEl9v5uEzcr) |
| whatnot.zendesk.com | Customer support |

### Stripe
- **Account**: `acct_1F9IrgEl9v5uEzcr` (live mode)
- **Publishable key**: `pk_live_51H8xZ7JfBfpFxY4xUwF11YtNaiMZOSFfZ5gANdgO8iFjwGQYH3iyIPcPNNPQkHFJS3whQjJLgDFT7WQ8DPB2HmEu00QqXJWe7M`

### StorageManager
- **Path**: `D:\temp\workspace\scan.db`
- **Findings**: 6 new + ~20 legacy (some duplicates — cleanup needed)
- **Endpoints**: 7 new + legacy
- **Query**: `python -c "from tools.storage import StorageManager; s=StorageManager(r'D:\temp\workspace').init(); print(s.get_findings())"`

### Cleanup
```powershell
adb -s emulator-5554 shell "am force-stop com.whatnot_mobile"  # Stop Pairip-bypassed app
adb -s emulator-5554 emu kill                                   # Shutdown emulator
```

### Next Steps
1. Hook `Buffer.read(byte[], int, int)` với JSON detection để capture Apollo GraphQL responses
2. ✅ **Web session tested** — RT → new AT → GraphQL works (PII + phone accessible)
3. ✅ **Pairip bypass restored** — attach mode + pm clear timing window
4. GraphQLer trên WSL2 — compile schema, fuzz IDOR/mutations
5. Test fund manipulation — `authorizePayment` với correct `MoneyInput`
6. WebSocket CSRF token replay — connect từ IP khác
7. StorageManager cleanup — remove duplicate findings
