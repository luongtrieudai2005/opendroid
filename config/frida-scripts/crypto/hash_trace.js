// Hash function tracer — logs all MessageDigest calls
Java.perform(function() {
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
            console.log('[HASH] getInstance: ' + algo);
            return this.getInstance(algo);
        };
        MessageDigest.digest.overload().implementation = function() {
            var result = this.digest();
            var hex = '';
            for (var i = 0; i < result.length; i++) {
                hex += ('0' + (result[i] & 0xFF).toString(16)).slice(-2);
            }
            var stack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
            console.log('[HASH] digest = ' + hex);
            console.log('[HASH] stack: ' + stack.split('\n').slice(0, 3).join(' -> '));
            return result;
        };
        console.log('[+] Hash tracer installed');
    } catch(e) { console.log('[-] Hash hook: ' + e); }

    try {
        var Mac = Java.use('javax.crypto.Mac');
        Mac.getInstance.overload('java.lang.String').implementation = function(algo) {
            console.log('[MAC] getInstance: ' + algo);
            return this.getInstance(algo);
        };
        console.log('[+] MAC tracer installed');
    } catch(e) { console.log('[-] MAC hook: ' + e); }
});
