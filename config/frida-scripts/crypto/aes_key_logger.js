// AES encryption key logger — hooks Cipher.init() to capture keys
Java.perform(function() {
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
            var encoded = key.getEncoded();
            if (encoded) {
                var hex = '';
                for (var i = 0; i < encoded.length; i++) {
                    hex += ('0' + (encoded[i] & 0xFF).toString(16)).slice(-2);
                }
                console.log('[CIPHER_KEY] ' + key.getAlgorithm() + ' key(' + hex + ') mode=' + mode);
            } else {
                console.log('[CIPHER_KEY] ' + key.getAlgorithm() + ' key (encoded=null) mode=' + mode);
            }
            return this.init(mode, key);
        };
        console.log('[+] AES key logger installed');
    } catch(e) { console.log('[-] Cipher hook: ' + e); }

    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyData, algo) {
            var hex = '';
            for (var i = 0; i < keyData.length; i++) {
                hex += ('0' + (keyData[i] & 0xFF).toString(16)).slice(-2);
            }
            console.log('[SECRETKEY_SPEC] algo=' + algo + ' key=' + hex);
            return this.$init(keyData, algo);
        };
        console.log('[+] SecretKeySpec hooked');
    } catch(e) { console.log('[-] SecretKeySpec: ' + e); }
});
