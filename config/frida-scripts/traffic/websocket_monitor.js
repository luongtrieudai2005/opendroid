// WebSocket connection monitor — hooks OkHttp WebSocket creation
Java.perform(function() {
    // Hook OkHttp WebSocket creation
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newWebSocket.overload('okhttp3.Request', 'okhttp3.WebSocketListener').implementation = function(request, listener) {
            console.log('[WS] newWebSocket: ' + request.url());
            return this.newWebSocket(request, listener);
        };
        console.log('[+] OkHttp WebSocket hooked');
    } catch(e) { console.log('[-] OkHttp WS: ' + e); }

    // Hook java.net.WebSocket (Android 14+)
    try {
        var WebSocket = Java.use('android.net.websocket.WebSocket');
        if (WebSocket) {
            WebSocket.connect.overload('java.net.URI', 'java.util.List', 'android.net.websocket.WebSocket.Listener').implementation = function(uri, protocols, listener) {
                console.log('[WS_ANDROID] connect: ' + uri.toString());
                return this.connect(uri, protocols, listener);
            };
            console.log('[+] Android WebSocket hooked');
        }
    } catch(e) {}

    // Hook raw socket connect to detect ws:// traffic
    try {
        var Socket = Java.use('java.net.Socket');
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
            var addrStr = addr.toString();
            if (addrStr.indexOf(':') > 0) {
                console.log('[SOCKET] connect: ' + addrStr + ' (timeout=' + timeout + ')');
            }
            return this.connect(addr, timeout);
        };
    } catch(e) {}

    console.log('[+] WebSocket monitor ready');
});
