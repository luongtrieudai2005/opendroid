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
