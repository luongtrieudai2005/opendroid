Java.perform(function() {
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
});
