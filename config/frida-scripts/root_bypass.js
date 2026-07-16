/*
 * Combined Root-Detection Bypass
 * Target: RootBeer + Bugsnag DeviceData + JailMonkey RootedCheck (Java)
 *         + libtool-checker.so (native, JNI export)
 *         + libc fopen/access fallback (an toàn cho native khác chưa recon được)
 *
 * Chạy bằng spawn mode để đảm bảo hook có hiệu lực TRƯỚC khi
 * Bugsnag/JailMonkey chạy check trong lúc app khởi động:
 *   frida -U -f <package_name> -l combined_bypass.js --no-pause
 */

Java.perform(function () {

    // ===== 1) RootBeer =====
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () {
            console.log("[RootBeer] isRooted() -> false");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
            console.log("[RootBeer] isRootedWithoutBusyBoxCheck() -> false");
            return false;
        };
        RootBeer.checkForRootNative.implementation = function () {
            console.log("[RootBeer] checkForRootNative() -> false");
            return false;
        };
    } catch (e) {
        console.log("[!] RootBeer không load được: " + e);
    }

    // ===== 2) Bugsnag DeviceData.isRooted() (private method) =====
    try {
        var DeviceData = Java.use("com.bugsnag.android.DeviceData");
        DeviceData.isRooted.implementation = function () {
            console.log("[Bugsnag] isRooted() -> false");
            return false;
        };
    } catch (e) {
        console.log("[!] Bugsnag DeviceData không load được: " + e);
    }

    // ===== 3) JailMonkey RootedCheck.isJailBroken(Context) - static entry =====
    try {
        var RootedCheck = Java.use("com.gantix.JailMonkey.Rooted.RootedCheck");
        RootedCheck.isJailBroken.implementation = function (context) {
            console.log("[JailMonkey] isJailBroken() -> false");
            return false;
        };
    } catch (e) {
        console.log("[!] JailMonkey RootedCheck không load được: " + e);
    }

    console.log("[*] Java-layer hooks installed.");
});

// ============================================================
// 4) Native: libtool-checker.so
//    export: Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot
// ============================================================
function hookNativeCheckForRoot() {
    var libName = "libtool-checker.so";
    var mod = Process.findModuleByName(libName);
    if (!mod) return false;

    var target = Module.findExportByName(libName, "Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot");
    if (!target) {
        console.log("[!] Không tìm thấy export checkForRoot trong " + libName);
        return false;
    }

    Interceptor.attach(target, {
        onLeave: function (retval) {
            console.log("[Native] checkForRoot() trả về " + retval + " -> ép về 0");
            retval.replace(0);
        }
    });
    console.log("[*] Đã hook native checkForRoot trong " + libName);
    return true;
}

// libtool-checker.so load qua System.loadLibrary trong static block của
// RootBeerNative -> có thể load SAU khi script này chạy, nên cần theo dõi
// dlopen thay vì chỉ hook 1 lần lúc start.
if (!hookNativeCheckForRoot()) {
    var dlopenFn = Module.findExportByName(null, "android_dlopen_ext") ||
                   Module.findExportByName(null, "dlopen");
    if (dlopenFn) {
        Interceptor.attach(dlopenFn, {
            onEnter: function (args) {
                this.path = args[0].readCString();
            },
            onLeave: function (retval) {
                if (this.path && this.path.indexOf("tool-checker") !== -1) {
                    console.log("[*] Phát hiện load libtool-checker.so, tiến hành hook...");
                    hookNativeCheckForRoot();
                }
            }
        });
        console.log("[*] Đang theo dõi dlopen chờ libtool-checker.so...");
    }
}

// ============================================================
// 5) Lưới an toàn tầng libc: chặn fopen()/access() cho path liên quan
//    su/busybox/magisk - phòng native nào khác chưa recon ra (bị strip/obfuscate)
// ============================================================
var suspiciousTokens = ["su", "busybox", "magisk", "supersu"];

function isSuspiciousPath(path) {
    if (!path) return false;
    var lower = path.toLowerCase();
    return suspiciousTokens.some(function (t) { return lower.indexOf(t) !== -1; });
}

["fopen", "fopen64"].forEach(function (fn) {
    var addr = Module.findExportByName(null, fn);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.path = args[0].readCString();
                this.hit = isSuspiciousPath(this.path);
            },
            onLeave: function (retval) {
                if (this.hit) {
                    console.log("[libc] " + fn + "(" + this.path + ") -> NULL (chặn)");
                    retval.replace(ptr(0));
                }
            }
        });
    }
});

var accessAddr = Module.findExportByName(null, "access");
if (accessAddr) {
    Interceptor.attach(accessAddr, {
        onEnter: function (args) {
            this.path = args[0].readCString();
            this.hit = isSuspiciousPath(this.path);
        },
        onLeave: function (retval) {
            if (this.hit) {
                console.log("[libc] access(" + this.path + ") -> -1 (chặn)");
                retval.replace(ptr(-1));
            }
        }
    });
}

console.log("[*] Native + libc hooks installed.");