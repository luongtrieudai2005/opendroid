
Java.perform(function() {
    // SSL unpin: TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.example.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(kms, tms, sr) {
            this.init.call(this, kms, [TrustManager.$new()], sr);
        };
        console.log('[+] SSL TrustManager bypassed');
    } catch(e) { console.log('[-] TrustManager: ' + e); }
    // OkHttp CertificatePinner
    try { Java.use('okhttp3.CertificatePinner').check.overload('java.lang.String', 'java.util.List').implementation = function() {}; console.log('[+] OkHttp pinner bypassed'); } catch(e) {}
    // WebView
    try { Java.use('android.webkit.WebViewClient').onReceivedSslError.implementation = function(v, h, e) { h.proceed(); }; console.log('[+] WebView SSL bypassed'); } catch(e) {}
    console.log('[+] SSL pinning bypassed');
});
