// Combined Frida script — auto-generated
// Includes: ssl_bypass/universal_unpin, traffic/traffic_dump
// =============================================

// === [ssl_bypass/universal_unpin] ===

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


// === [traffic/traffic_dump] ===
// Dump all HTTP traffic via Frida
Java.perform(function() {
    // 1. Hook OkHttp EventListener
    try {
        var EventListener = Java.use('okhttp3.EventListener$Companion');
        if (EventListener) {
            EventListener.NONE.value = EventListener.$new();
            console.log('[+] OkHttp EventListener found');
        }
    } catch(e) {}

    // 2. Log all socket writes
    try {
        var Socket = Java.use('java.net.Socket');
        Socket.getOutputStream.implementation = function() {
            var os = this.getOutputStream();
            console.log('[Socket] getOutputStream for ' + this.getInetAddress() + ':' + this.getPort());
            return os;
        };
    } catch(e) {}

    // 3. Hook URLConnection / HttpsURLConnection opening
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var conn = this.openConnection();
            console.log('[URL] openConnection: ' + this.toString());
            return conn;
        };
    } catch(e) {}

    // 4. Hook ProcessBuilder for any curl/wget calls
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function() {
            var cmd = this.command();
            if (cmd) {
                var cmdStr = '';
                for (var i = 0; i < cmd.size(); i++) {
                    cmdStr += cmd.get(i) + ' ';
                }
                console.log('[Process] ' + cmdStr);
            }
            return this.start();
        };
    } catch(e) {}

    // 5. Hook Android HttpClient if present
    try {
        var AndroidHttpClient = Java.use('android.net.http.AndroidHttpClient');
        AndroidHttpClient.execute.overload('org.apache.http.HttpHost', 'org.apache.http.HttpRequest', 'org.apache.http.client.ResponseHandler').implementation = function(host, req, handler) {
            console.log('[HttpClient] execute: ' + host.toString() + ' ' + req.getRequestLine());
            return this.execute(host, req, handler);
        };
    } catch(e) {}

    console.log('[+] All traffic hooks installed');
    console.log('[+] Watch Frida output for API calls');
});
