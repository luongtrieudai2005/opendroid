// Stalker G2-lite — safe Dart call-event recon for Flutter AOT
//
// Uses Stalker in "events:call" mode (NOT per-block transform — that caused
// Dart SIGTRAP asserts on the IO isolate). Only call events whose target
// address falls inside libapp.so._kDartIsolateSnapshotInstructions are
// tallied. Much lighter instrumentation -> dramatically lower crash risk.
//
// It follows the Dart UI isolate ("1.ui"/"1.raster") rather than "1.io" and
// auto-stop after ACTIVITY_MS with no calls. Stop immediately if the app
// looks corrupted (call density spikes) — best effort guard.
//
// Usage:
//   frida -H 127.0.0.1:27042 -n <process_name> -l stalker_events_lite.js
//       (auto-starts; summarises on rpc stop() or window end)
//
// Events:
//   {t:'ready'|'follow'|'summary'|'stop'|'guard'}

'use strict';

const DART_ISOLATE_OFF = 0x7b5e40;
const DART_TEXT_END = 0x7a0000 + 0xc99720;
const TEXT_START = 0x7a0000;          // libapp.so .text start (VM + isolate)
const WINDOW_MS = 30000;

let app = null;
let textLow = null;
let textHigh = null;
let watchedTid = null;
let countMap = {};        // '0xOFF' → appearance count (accumulated)
let windowTimer = null;
let active = false;
let _debugged = 0;

function hex(p) { return '0x' + p.toString(16); }

function comm(tid) {
  try {
    const f = new File('/proc/self/task/' + tid + '/comm', 'r');
    const s = f.readText(64).trim();
    f.close();
    return s;
  } catch (e) { return ''; }
}

function findUiThread() {
  const threads = Process.enumerateThreads();
  for (const t of threads) {
    const c = comm(t.id);
    if (/^1\.ui$|^1\.raster$|^Dart.*ui/i.test(c)) return t.id;
  }
  return null;
}

function start() {
  if (active) stop();

  app = Process.findModuleByName('libapp.so');
  if (!app) { console.log('[LITE] error: libapp.so not loaded'); return; }
  textLow = app.base.add(TEXT_START);
  textHigh = app.base.add(DART_TEXT_END);

  const tid = findUiThread();
  if (tid === null) { console.log('[LITE] error: no Dart UI thread'); return; }
  watchedTid = tid;
  countMap = {};
  active = true;

  try {
    Stalker.follow(tid, {
      events: { call: true },
      onCallSummary: function (summary) {
        if (!summary) return;
        // Summary is a dict keyed by call address (string '0x...').
        for (const k of Object.keys(summary)) {
          if (!k.startsWith('0x')) continue;
          const addr = ptr(k);
          if (addr.compare(textLow) >= 0 && addr.compare(textHigh) < 0) {
            const off = hex(addr.sub(app.base));
            // each summary batch lists the address at most once; every batch
            // that shows it increments the tally
            countMap[off] = (countMap[off] || 0) + 1;
          }
        }
      },
    });
  } catch (e) {
    console.log('[LITE] follow failed: ' + e);
    active = false;
    return;
  }

  console.log('[LITE] follow tid=' + watchedTid + ' comm=' + comm(tid) +
              ' text_lo=' + hex(textLow) + ' text_hi=' + hex(textHigh));
  console.log('[LITE] interacting... ' + (WINDOW_MS / 1000) + 's window');
  windowTimer = setTimeout(function () { stop(); }, WINDOW_MS);
}

function stop() {
  if (!active) return;
  active = false;
  if (windowTimer) { clearTimeout(windowTimer); windowTimer = null; }
  if (watchedTid !== null) {
    try { Stalker.unfollow(watchedTid); } catch (e) {}
    watchedTid = null;
  }
  const rows = Object.entries(countMap)
      .map(function (e) { return [e[0], e[1]]; })
      .sort(function (a, b) { return b[1] - a[1]; });
  countMap = {};
  console.log('[LITE] summary ' + JSON.stringify(rows.slice(0, 60)));
  console.log('[LITE] stopped');
}

function status() {
  return { active: active, tid: watchedTid,
           text_lo: textLow ? hex(textLow) : null,
           text_hi: textHigh ? hex(textHigh) : null };
}

rpc.exports = { start: start, stop: stop, status: status };
setTimeout(start, 1000);
console.log('[LITE] loaded');