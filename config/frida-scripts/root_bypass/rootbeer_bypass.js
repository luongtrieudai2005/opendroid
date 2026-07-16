
Java.perform(function() {
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() { console.log('[RootBeer] isRooted -> false'); return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { console.log('[RootBeer] isRootedWBC -> false'); return false; };
        RootBeer.checkForRootNative.implementation = function() { console.log('[RootBeer] checkForRootNative -> false'); return false; };
        console.log('[+] RootBeer bypassed');
    } catch(e) { console.log('[-] RootBeer: ' + e); }
    try {
        var DeviceData = Java.use('com.bugsnag.android.DeviceData');
        DeviceData.isRooted.implementation = function() { console.log('[Bugsnag] isRooted -> false'); return false; };
    } catch(e) {}
    console.log('[+] Root detection bypassed');
});
