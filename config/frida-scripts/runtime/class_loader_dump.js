// Dump all loaded classes matching a filter
// Usage: Set FILTER env var, or leave empty to dump all
Java.perform(function() {
    var filter = FILTER || '';
    console.log('[CLASSDUMP] Enumerating classes' + (filter ? ' matching: ' + filter : ''));
    var allClasses = Java.enumerateLoadedClassesSync();
    var matched = [];
    allClasses.forEach(function(cls) {
        if (!filter || cls.toLowerCase().indexOf(filter.toLowerCase()) >= 0) {
            matched.push(cls);
        }
    });
    matched.sort();
    console.log('[CLASSDUMP] Total loaded: ' + allClasses.length + ', Matched: ' + matched.length);
    matched.forEach(function(cls) {
        console.log(cls);
    });
});
