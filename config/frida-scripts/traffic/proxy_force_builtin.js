
Java.perform(function() {
    var proxyHost = '127.0.0.1';
    var proxyPort = 8080;
    try {
        var OkHttpBuilder = Java.use('okhttp3.OkHttpClient$Builder');
        var Proxy = Java.use('java.net.Proxy');
        var InetSocket = Java.use('java.net.InetSocketAddress');
        var myProxy = Proxy.$new(Proxy.Type.HTTP, InetSocket.$new(proxyHost, proxyPort));
        OkHttpBuilder.build.implementation = function() {
            this.proxy(myProxy);
            console.log('[Proxy] OkHttp proxy forced to ' + proxyHost + ':' + proxyPort);
            return this.build();
        };
        console.log('[+] OkHttp proxy forced');
    } catch(e) { console.log('[-] OkHttp proxy: ' + e); }
});
