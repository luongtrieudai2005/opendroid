// Stalker G2 — Dart block-summary recon for Flutter AOT (libapp.so)
//
// Follows the Dart IO isolate thread and uses Stalker's transform iterator
// to count native block executions inside the Dart business-logic code range
// (libapp.so._kDartIsolateSnapshotInstructions). The user triggers an in-app
// action; during the window every native block that begins execution in the
// Dart code is tallied → "Dart block-offset → count" recon map.
//
// Usage:
//   frida -H 127.0.0.1:27042 -n <process_name> -l stalker_call_summary.js
//   --eval "rpc.exports.start(12000).then(()=>console.log('started'))"
//
// Events (type 'send'):
//   {t:'ready',  dart_lo, dart_hi}
//   {t:'follow', tid, comm}
//   {t:'summary', rows:[[off,count],...]}   sorted desc, up to 50
//   {t:'stop'}

'use strict';

const DART_ISOLATE_OFF = 0x7b5e40;
const DART_TEXT_END = 0x7a0000 + 0xc99720;

let app = null;
let dartLow = null;
let dartHigh = null;
let watchedTid = null;
let summaryMap = {};      // '0xOFFSET' → count
let stopTimer = null;
let active = false;
let busyWindow = 0;
let _debug = false;

const CALM_MS = 3000;     // auto-stop N ms after last Dart activity

function hex(p) { return '0x' + p.toString(16); }

function comm(tid) {
  try {
    const f = new File('/proc/self/task/' + tid + '/comm', 'r');
    const s = f.readText(64).trim();
    f.close();
    return s;
  } catch (e) { return ''; }
}

function findDartIoThread() {
  const threads = Process.enumerateThreads();
  for (const t of threads) {
    const c = comm(t.id);
    if (/^1\.io$|^1\.io /.test(c) || /dart:io/.test(c)) return t.id;
  }
  for (const t of threads) {
    const c = comm(t.id);
    if (/\.io($|[ ._])|io\.worker/i.test(c)) return t.id;
  }
  return null;
}

function start(ms) {
  if (active) stop();

  app = Process.findModuleByName('libapp.so');
  if (!app) { send({ t: 'error', msg: 'libapp.so not loaded' }); return; }
  dartLow = app.base.add(DART_ISOLATE_OFF);
  dartHigh = app.base.add(DART_TEXT_END);

  const tid = findDartIoThread();
  if (tid === null) {
    send({ t: 'error', msg: 'no Dart IO thread found' });
    return;
  }

  watchedTid = tid;
  summaryMap = {};
  active = true;

  try {
    Stalker.follow(tid, {
      transform: function (iterator) {
        let block;
        let inRange = 0;
        while ((block = iterator.next()) !== null) {
          if (block.address.compare(dartLow) >= 0 &&
              block.address.compare(dartHigh) < 0) {
            const off = hex(block.address.sub(app.base));
            summaryMap[off] = (summaryMap[off] || 0) + 1;
            inRange++;
          }
        }
        if (inRange > 0) {
          busyWindow = Date.now();
          if (_debug) console.log('[block] +' + inRange +
                                  ' total=' + Object.keys(summaryMap).length);
        }
      },
    });
  } catch (e) {
    send({ t: 'error', msg: 'follow failed: ' + e });
    active = false;
    return;
  }

  send({ t: 'ready', dart_lo: hex(dartLow), dart_hi: hex(dartHigh) });
  send({ t: 'follow', tid: watchedTid, comm: comm(tid) });

  // Auto-stop: hard cap, plus early stop when the app calms down (no blocks
  // in libapp.so for CALM_MS) so we don't wait out dead time after an action.
  const cap = Math.min(ms || 12000, 60000);
  stopTimer = setTimeout(function () { stop(); }, cap);
  const calmTimer = setInterval(function () {
    if (!active) { clearInterval(calmTimer); return; }
    if (busyWindow > 0 && Date.now() - busyWindow > CALM_MS) {
      clearInterval(calmTimer);
      send({ t: 'calm-stop', idle_ms: Date.now() - busyWindow });
      stop();
    }
  }, 500);
}

function stop() {
  if (watchedTid !== null) {
    try { Stalker.unfollow(watchedTid); } catch (e) {}
    watchedTid = null;
  }
  if (stopTimer) { clearTimeout(stopTimer); stopTimer = null; }
  if (!active) return;
  active = false;

  const rows = Object.entries(summaryMap)
      .map(function (e) { return [e[0], e[1]]; })
      .sort(function (a, b) { return b[1] - a[1]; });
  summaryMap = {};
  send({ t: 'summary', rows: rows.slice(0, 50) });
  send({ t: 'stop' });
}

function status() {
  return { active: active, tid: watchedTid,
           dart_lo: dartLow ? hex(dartLow) : null,
           dart_hi: dartHigh ? hex(dartHigh) : null };
}

rpc.exports = {
  start: start,
  stop: stop,
  status: status,
  setDebug: function (v) { _debug = !!v; return _debug; },
};
send({ t: 'loaded' });