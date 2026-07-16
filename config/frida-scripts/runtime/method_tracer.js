// Generic method tracer — call with CLASS_NAME env variable
// Usage: frida -U -n com.target.app -l method_tracer.js --eval "var TARGET_CLASS='okhttp3.OkHttpClient'"
Java.perform(function() {
    var targetClass = TARGET_CLASS || 'com.example.MainActivity';
    console.log('[TRACER] Target class: ' + targetClass);

    try {
        var Cls = Java.use(targetClass);
        var methods = Object.getOwnPropertyNames(Cls.__proto__);
        console.log('[TRACER] Found ' + methods.length + ' methods/properties');

        methods.forEach(function(m) {
            if (typeof Cls[m] === 'function' && m.indexOf('$') === -1) {
                try {
                    var overloads = Cls[m].overloads;
                    if (overloads) {
                        overloads.forEach(function(o, idx) {
                            o.implementation = function() {
                                var args = [];
                                for (var i = 0; i < arguments.length; i++) {
                                    var a = arguments[i];
                                    if (a === null) args.push('null');
                                    else if (typeof a === 'object' && a.toString) args.push(a.toString().substring(0, 100));
                                    else args.push(String(a).substring(0, 100));
                                }
                                console.log('[TRACE] ' + targetClass + '.' + m + '(' + args.join(', ') + ')');
                                var start = Date.now();
                                var ret = o.apply(this, arguments);
                                var elapsed = Date.now() - start;
                                if (elapsed > 100) console.log('[TRACE] ' + targetClass + '.' + m + ' took ' + elapsed + 'ms');
                                return ret;
                            };
                        });
                    }
                } catch(e) {}
            }
        });
        console.log('[TRACER] Hooked ' + targetClass + ' methods');
    } catch(e) {
        console.log('[TRACER] Error hooking ' + targetClass + ': ' + e);
    }
});
