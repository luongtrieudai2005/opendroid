// Force OkHttp proxy to Burp, dump all HTTP traffic
Java.perform(function() {
    // Dump all network calls via OkHttp event listener
    try {
        var EventListener = Java.use('okhttp3.OkHttpClient$Builder');
        EventListener.eventListener.implementation = function(listener) {
            console.log('[+] OkHttp EventListener set');
            return this.eventListener(listener);
        };
    } catch(e) { console.log('[-] OkHttp builder not found: ' + e); }

    // Hook ProxySelector
    try {
        var ProxySelector = Java.use('java.net.ProxySelector');
        ProxySelector.select.implementation = function(uri) {
            var result = this.select(uri);
            console.log('[Proxy] select: ' + uri.toString());
            var proxy = Java.use('java.net.Proxy');
            var inetSocket = Java.use('java.net.InetSocketAddress');
            var myProxy = proxy.$new(proxy.Type.HTTP, inetSocket.$new('127.0.0.1', 8080));
            var ArrayList = Java.use('java.util.ArrayList');
            var list = ArrayList.$new();
            list.add(myProxy);
            return list;
        };
        console.log('[+] ProxySelector hooked');
    } catch(e) { console.log('[-] ProxySelector hook failed: ' + e); }
    
    // Hook OkHttpClient.Builder proxy
    try {
        var OkHttpBuilder = Java.use('okhttp3.OkHttpClient$Builder');
        OkHttpBuilder.build.implementation = function() {
            console.log('[OkHttp] Building client...');
            // Set proxy
            var proxy = Java.use('java.net.Proxy');
            var inetSocket = Java.use('java.net.InetSocketAddress');
            var myProxy = proxy.$new(proxy.Type.HTTP, inetSocket.$new('127.0.0.1', 8080));
            this.proxy(myProxy);
            return this.build();
        };
        console.log('[+] OkHttp proxy forced');
    } catch(e) { console.log('[-] OkHttp proxy hook failed: ' + e); }

    console.log('[+] Network hooks installed');
});
