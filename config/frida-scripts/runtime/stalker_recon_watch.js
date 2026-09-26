// Stalker G2 — Dart block-summary recon (watch mode)
//
// Persistent watcher: follows the Flutter app's Dart IO isolate thread and
// periodically dumps which native blocks in libapp.so._kDartIsolateSnapshot*
// executed during the window. Run this in background, then interact with the
// app; every ~4s a JSON summary of visited Dart-code offsets + counts is
// written to the log. Pure recon build on Stalker.
//
// Usage:
//   frida -H 127.0.0.1:27042 -n <process_name> -l stalker_recon_watch.js
//       -o workspace/stalker_watch.log  (keep running in a terminal)
//   rpc.exports.startDrift(ms)  → rebase tracking on the current libapp base
//
// Log lines:
//   [WATCH] follow tid=<n> comm=<c> dart_lo=<..> dart_hi=<..>
//   [WATCH] summary <json>   (rows: [[off,count],...], offsets relative to
//                             libapp.so base as "0x…")

'use strict';

const DART_ISOLATE_OFF = 0x7b5e40;
const DART_TEXT_END = 0x7a0000 + 0xc99720;
const DUMP_MS = 4000;
const WINDOW_MS = 120000;

let app = null;
let dartLow = null;
let dartHigh = null;
let watchedTid = null;
let summaryMap = {};
let windowTimer = null;
let dumpTimer = null;
let active = false;

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

function dump() {
  if (!active) return;
  const rows = Object.entries(summaryMap)
      .map(function (e) { return [e[0], e[1]]; })
      .sort(function (a, b) { return b[1] - a[1]; });
  console.log('[WATCH] summary ' + JSON.stringify(rows.slice(0, 60)));
  // keep only top-visited to avoid unbounded memory
  summaryMap = {};
}

function start() {
  if (active) { stop(); }

  app = Process.findModuleByName('libapp.so');
  if (!app) { console.log('[WATCH] error: libapp.so not loaded'); return; }
  dartLow = app.base.add(DART_ISOLATE_OFF);
  dartHigh = app.base.add(DART_TEXT_END);

  const tid = findDartIoThread();
  if (tid === null) { console.log('[WATCH] error: no Dart IO thread'); return; }

  watchedTid = tid;
  summaryMap = {};
  active = true;

  try {
    Stalker.follow(tid, {
      transform: function (iterator) {
        let block;
        while ((block = iterator.next()) !== null) {
          if (block.address.compare(dartLow) >= 0 &&
              block.address.compare(dartHigh) < 0) {
            summaryMap[hex(block.address.sub(app.base))] =
                (summaryMap[hex(block.address.sub(app.base))] || 0) + 1;
          }
        }
      },
    });
  } catch (e) {
    console.log('[WATCH] follow failed: ' + e);
    active = false;
    return;
  }

  console.log('[WATCH] follow tid=' + watchedTid + ' comm=' + comm(tid) +
              ' dart_lo=' + hex(dartLow) + ' dart_hi=' + hex(dartHigh));
  console.log('[WATCH] interacting... Now use the app; summary every ' +
              (DUMP_MS / 1000) + 's for ' + (WINDOW_MS / 1000) + 's.');

  dumpTimer = setInterval(dump, DUMP_MS);
  windowTimer = setTimeout(stop, WINDOW_MS);
}

function stop() {
  if (!active) return;
  active = false;
  if (dumpTimer) { clearInterval(dumpTimer); dumpTimer = null; }
  if (windowTimer) { clearTimeout(windowTimer); windowTimer = null; }
  if (watchedTid !== null) {
    try { Stalker.unfollow(watchedTid); } catch (e) {}
    watchedTid = null;
  }
  console.log('[WATCH] stopped');
}

rpc.exports = { start: start, stop: stop,
                startDrift: function (ms) {
                  stop(); start();
                  return status();
                },
                status: function () {
                  return { active: active, tid: watchedTid,
                           dart_lo: dartLow ? hex(dartLow) : null };
                } };

// Auto-start for detached/background usage; also available via RPC.
setTimeout(start, 1000);
console.log('[WATCH] loaded — auto-start in 1s');