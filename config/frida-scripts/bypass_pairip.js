// Pairip License Bypass — attach mode only (Java.perform broken in -f spawn mode on Android 16)
// Usage:
//   1. adb -s emulator-5554 shell "pm clear com.whatnot_mobile"
//   2. adb -s emulator-5554 shell "monkey -p com.whatnot_mobile 1"
//   3. Start-Sleep -Seconds 1
//   4. $pid = <get PID from ps>
//   5. frida -H 127.0.0.1:27043 -p $pid -l bypass_pairip.js -q
//
// Why it works: pm clear removes Pairip's cached fail state. Pairip then contacts
// Play Licensing service, which takes 3-5s to timeout (no Google Play on AVD).
// We attach within 1s and hook checkLicense before the callback returns.
// Java.perform() (async) only works in attach mode, NOT spawn mode on Android 16.

var installed = false;

function tryHook() {
  if (installed) return;
  Java.perform(function () {
    try {
      var L = Java.use('com.pairip.licensecheck.LicenseClient');
      var S = Java.use('com.pairip.licensecheck.LicenseClient$LicenseCheckState');

      // Layer 1: Bypass checkLicense entirely
      L.checkLicense.overload('android.content.Context').implementation =
        function (ctx) { return; };

      // Layer 2: Set LOCAL_CHECK_REPORTED => makes initializeLicenseCheck return early
      L.licenseCheckState.value = S.LOCAL_CHECK_REPORTED.value;

      // Layer 3: Suppress handleError (so it never shows dialog)
      L.handleError.overload(
        'com.pairip.licensecheck.LicenseCheckException'
      ).implementation = function (ex) { };

      // Layer 4+5: Block error/paywall activities
      L.startErrorDialogActivity.implementation = function () { };
      L.startPaywallActivity.implementation = function () { };

      installed = true;
    } catch (e) {
      setTimeout(tryHook, 500);
    }
  });
}

tryHook();
