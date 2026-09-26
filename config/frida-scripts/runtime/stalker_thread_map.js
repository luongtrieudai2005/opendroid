// Stalker G1 — Thread & Module Map for Flutter AOT (libapp.so)
//
// Enumerates loaded native modules and threads, then flags the Dart isolate
// threads (i.e. threads whose instruction pointer currently sits in the
// libapp.so / libflutter.so code regions). Dart AOT code lives in
// libapp.so._kDartIsolateSnapshotInstructions; tracing those threads with
// Stalker lets us observe business-logic execution (network/crypto/order).
//
// Usage:  frida -H 127.0.0.1:27042 -n <process_name> -l stalker_thread_map.js
//
// Output lines:
//   [MOD] name base=0x.. size=0x..
//   [THR] id=<n> state=<running|waiting> pc=0x.. region=<name|-> dart=<yes|no>

'use strict';

// Dart AOT snapshot symbol offsets from readelf on libapp.so (x86_64).
const DART_ISOLATE_OFF = 0x7b5e40;   // _kDartIsolateSnapshotInstructions
const DART_TEXT_END = 0x7a0000 + 0xc99720; // .text end (VM snapshot + isolate)

function hex(ptr) {
  return ptr ? '0x' + ptr.toString(16).padStart(12, '0') : 'n/a';
}

function moduleAt(addr, modules) {
  for (const m of modules) {
    const base = m.base;
    const end = base.add(m.size);
    if (addr.compare(base) >= 0 && addr.compare(end) < 0) {
      return m;
    }
  }
  return null;
}

function commFor(tid) {
  try {
    const f = new File('/proc/self/task/' + tid + '/comm', 'r');
    const name = f.readText(64).trim();
    f.close();
    return name;
  } catch (e) {
    return '-';
  }
}

function main() {
  const mods = Process.enumerateModules();
  console.log('[.] modules: ' + mods.length);

  const interesting = mods.filter(m =>
    /libapp\.so|libflutter\.so|libsigner\.so/.test(m.name));
  for (const m of interesting) {
    console.log('[MOD] ' + m.name + ' base=' + hex(m.base) +
                ' size=0x' + m.size.toString(16));
  }

  // Dart isolate code target range (runtime addresses).
  const app = Process.findModuleByName('libapp.so');
  if (!app) {
    console.log('[!] libapp.so not loaded (not a Flutter app?)');
    return;
  }
  const dartLow = app.base.add(DART_ISOLATE_OFF);
  const dartHigh = app.base.add(DART_TEXT_END);
  console.log('[+] Dart isolate code range: ' + hex(dartLow) + ' .. ' +
              hex(dartHigh));

  const sum = { running: 0, waiting: 0, inDart: 0, inFlutter: 0,
              interesting: 0 };

  try {
    const threads = Process.enumerateThreads();
    console.log('[.] enumerateThreads -> ' + threads.length + ' threads');
    for (const t of threads) {
      try {
        const pc = t.context.pc;
        sum.total = (sum.total || 0) + 1;
        const m = moduleAt(pc, mods);
        const inDart = pc.compare(dartLow) >= 0 && pc.compare(dartHigh) < 0;
        const inFlutter = m && /libflutter/.test(m.name);
        const comm = commFor(t.id);
        const interesting = inDart || inFlutter
            || /dart|\.ui|\.io|isolate|worker/i.test(comm);
        if (inDart) sum.inDart++;
        if (inFlutter) sum.inFlutter++;
        if (interesting) sum.interesting++;
        if (t.state === 'running') sum.running++; else sum.waiting++;
        if (interesting) {
          console.log('[THR] id=' + t.id + ' state=' + t.state +
                      ' pc=' + hex(pc) + ' region='
                      + (m ? m.name : '-')
                      + ' comm=' + comm
                      + ' dart=' + (inDart ? 'YES' : 'no'));
        }
      } catch (e) {
        console.log('[!] thread ' + t.id + ' ctx error: ' + e);
      }
    }
    console.log('[=] total=' + (sum.total || 0)
                + ' running=' + sum.running + ' waiting=' + sum.waiting
                + ' threads-in-dart-range=' + sum.inDart
                + ' threads-in-libflutter=' + sum.inFlutter
                + ' interesting(named/ui/io/dart)=' + sum.interesting);
    console.log('[=] All threads shown are idle; the Dart isolate usually has'
                + ' I/O or UI threads in libc (futex). Trigger an action then '
                + 're-scan (G2) to see Dart code execute.');
  } catch (e) {
    console.log('[!] enumerateThreads failed: ' + e + '\n' + e.stack);
  }

  // Freeze the FPU/trap so later Stalker use doesn't trip over libc wrappers.
  Process.setExceptionHandler((detail) => {
    console.log('[!] EXCEPTION @ ' + hex(detail.address) + ' ' +
                detail.type);
    return true;
  });
}

setImmediate(main);