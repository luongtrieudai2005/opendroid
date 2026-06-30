param(
    [string]$Device = "emulator-5554",
    [string]$Package = "",
    [string]$Port = "27042"
)

Write-Host "=== Starting frida-server on $Device ==="

# Kill old frida-server
adb -s $Device shell "pkill frida-server" 2>$null

# Start fresh
adb -s $Device shell "nohup /data/local/tmp/frida-server-x86_64 -D -l 0.0.0.0:$Port &"

Start-Sleep -Seconds 2

# Verify
$running = adb -s $Device shell "ps -A 2>/dev/null || ps" | Select-String "frida-server"
if ($running) {
    Write-Host "frida-server OK (PID: $($running -replace '\s+', ' '))"
} else {
    Write-Host "FAIL: frida-server not running!"
    exit 1
}

# Forward port
adb -s $Device forward tcp:$Port tcp:$Port

if ($Package) {
    Write-Host "Spawning $Package ..."
    frida -H 127.0.0.1:$Port -f $Package -q
}
