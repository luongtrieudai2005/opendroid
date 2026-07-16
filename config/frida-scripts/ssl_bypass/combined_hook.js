// Force proxy + SSL unpin
Java.perform(function() {
    // SSL unpin
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
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function(keyManagers, trustManagers, secureRandom) {
            this.init.call(this, keyManagers, [TrustManager.$new()], secureRandom);
        };
        try { Java.use('okhttp3.CertificatePinner').check.overload('java.lang.String', 'java.util.List').implementation = function() {}; } catch(e) {}
        try { Java.use('android.webkit.WebViewClient').onReceivedSslError.implementation = function(view, handler, error) { handler.proceed(); }; } catch(e) {}
        console.log('[+] SSL pinning bypassed');
    } catch(e) { console.log('[-] SSL unpin error: ' + e); }

    // Force proxy
    try {
        var proxyClass = Java.use('java.net.Proxy');
        var inetSocket = Java.use('java.net.InetSocketAddress');
        var myProxy = proxyClass.$new(proxyClass.Type.HTTP, inetSocket.$new('127.0.0.1', 8080));

        var OkHttpBuilder = Java.use('okhttp3.OkHttpClient$Builder');
        OkHttpBuilder.build.implementation = function() {
            this.proxy(myProxy);
            return this.build();
        };
        console.log('[+] Proxy forced to 127.0.0.1:8080');
    } catch(e) { console.log('[-] OkHttp proxy hook failed: ' + e); }

    console.log('[+] All hooks ready');
});
