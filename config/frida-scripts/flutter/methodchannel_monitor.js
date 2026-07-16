// Flutter MethodChannel monitor — intercept Dart ↔ native communication
// MethodChannel is how Flutter apps communicate with native Android/iOS code
// This is critical for auth, crypto, storage operations that Dart delegates to native
Java.perform(function() {
    // Hook Flutter MethodChannel on the Java side
    try {
        var MethodChannel = Java.use('io.flutter.plugin.common.MethodChannel');
        MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object').implementation = function(method, args) {
            console.log('[MethodChannel] invoke: ' + method);
            if (args) console.log('[MethodChannel] args: ' + JSON.stringify(args.toString()));
            return this.invokeMethod(method, args);
        };
        MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object', 'io.flutter.plugin.common.MethodChannel$Result').implementation = function(method, args, result) {
            console.log('[MethodChannel] invoke (with result): ' + method);
            if (args) console.log('[MethodChannel] args: ' + args.toString());
            return this.invokeMethod(method, args, result);
        };
        console.log('[+] Flutter MethodChannel hooked');
    } catch(e) { console.log('[-] MethodChannel hook: ' + e); }

    // Hook Flutter BasicMessageChannel
    try {
        var BasicMessageChannel = Java.use('io.flutter.plugin.common.BasicMessageChannel');
        BasicMessageChannel.send.overload('java.lang.Object').implementation = function(msg) {
            console.log('[BasicChannel] send: ' + msg);
            return this.send(msg);
        };
        console.log('[+] BasicMessageChannel hooked');
    } catch(e) { console.log('[-] BasicChannel hook: ' + e); }

    // Hook Flutter EventChannel
    try {
        var EventChannel = Java.use('io.flutter.plugin.common.EventChannel');
        EventChannel.setStreamHandler.implementation = function(handler) {
            console.log('[EventChannel] setStreamHandler');
            return this.setStreamHandler(handler);
        };
        console.log('[+] EventChannel hooked');
    } catch(e) { console.log('[-] EventChannel hook: ' + e); }

    console.log('[+] Flutter channel monitor active');
});
