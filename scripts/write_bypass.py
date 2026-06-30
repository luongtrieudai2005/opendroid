#!/usr/bin/env python3
"""Write Frida bypass scripts with proper encoding (no BOM)."""
import os

SCRIPTS = {
    "bypass_mvp.js": """Java.perform(function() {
    console.log('[!] Bypass starting...');
    
    // Block System.exit
    try {
        Java.use('java.lang.System').exit.overload('int').implementation = function(code) {
            console.log('[!] System.exit(' + code + ') blocked');
        };
    } catch(e) { console.log('[!] exit hook fail: ' + e); }
    
    // Pairip
    try {
        var L = Java.use('com.pairip.licensecheck.LicenseClient');
        var S = Java.use('com.pairip.licensecheck.LicenseClient$LicenseCheckState');
        L.checkLicense.overload('android.content.Context').implementation = function(ctx) {
            console.log('[!] checkLicense skipped');
        };
        L.licenseCheckState.value = S.LOCAL_CHECK_REPORTED.value;
        L.handleError.overload('com.pairip.licensecheck.LicenseCheckException').implementation = function(ex) {
            console.log('[!] handleError suppressed');
        };
        L.startErrorDialogActivity.implementation = function() {
            console.log('[!] Error dialog blocked');
        };
        L.startPaywallActivity.implementation = function() {
            console.log('[!] Paywall blocked');
        };
        console.log('[!] Pairip bypass OK');
    } catch(e) { console.log('[!] Pairip fail: ' + e); }
    
    console.log('[!] Bypass ready');
});
""",
}

for name, content in SCRIPTS.items():
    path = os.path.join(r'D:\AndroidPentest\config\frida-scripts', name)
    with open(path, 'w', encoding='ascii') as f:
        f.write(content.lstrip('\n'))
    print(f'Written: {path} ({len(content)} bytes)')
