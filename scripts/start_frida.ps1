param(
    [string]$Device = "emulator-5554",
    [string]$Package = "",
    [string]$Port = "27042"
)

Write-Host "=== Starting frida-server on $Device ==="

Write-Host "[*] Restarting adbd as root..."
$rootResult = adb -s $Device root 2>&1
Write-Host "    $rootResult"
Start-Sleep -Seconds 2

Write-Host "[*] Disabling SELinux..."
adb -s $Device shell "setenforce 0" 2>&1 | Out-Null

# Kill old frida-server
adb -s $Device shell "pkill -9 frida-server" 2>$null
Start-Sleep -Seconds 1

# Get actual filename (handle version suffix)
$fridaBin = adb -s $Device shell "ls /data/local/tmp/frida-server*" 2>$null
if (-not $fridaBin) {
    Write-Host "ERROR: No frida-server binary found in /data/local/tmp/"
    exit 1
}

# Start fresh
Write-Host "[*] Starting frida-server..."
$fridaBin = $fridaBin.Trim()
adb -s $Device shell "nohup $fridaBin -D -l 0.0.0.0:$Port > /dev/null 2>&1 &"
Start-Sleep -Seconds 2

# Verify — phải thấy "root" ở cột đầu
$running = adb -s $Device shell "ps -A 2>/dev/null | grep frida-server"
if ($running) {
    Write-Host "frida-server OK: $($running.Trim())"
    # Kiểm tra user
    if ($running -match "^root") {
        Write-Host "[OK] Running as ROOT"
    } else {
        Write-Host "[WARN] NOT running as root! User: $(($running -split '\s+')[0])"
    }
} else {
    Write-Host "FAIL: frida-server not running!"
    exit 1
}

# Forward port
adb -s $Device forward tcp:$Port tcp:$Port
Write-Host "[*] Port $Port forwarded"

if ($Package) {
    Write-Host "Spawning $Package ..."
    frida -H 127.0.0.1:$Port -f $Package -q
}