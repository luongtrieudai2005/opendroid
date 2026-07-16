
Java.perform(function() {
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defVal) {
            var val = this.getString(key, defVal);
            console.log('[SP] getString(' + key + ') = ' + val);
            return val;
        };
        var Editor = Java.use('android.content.SharedPreferences$Editor');
        Editor.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, val) {
            console.log('[SP] putString(' + key + ', ' + val + ')');
            return this.putString(key, val);
        };
        console.log('[+] SharedPreferences hooked');
    } catch(e) { console.log('[-] SP hook: ' + e); }
});
