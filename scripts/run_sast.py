"""Run SAST over a decompiled APK tree and (optionally) persist + report.

Usage (PowerShell)::

    python scripts\\run_sast.py -Jadx workspace\\jadx\\com.linkedin.android -Target 1
    python scripts\\run_sast.py -Jadx workspace\\jadx\\com.linkedin.android  # no DB

Prints a summary by severity/rule and the top findings with file:line refs,
then (if -Target given) rewrites the target's recon artifacts including
``source/sast.md``.
"""
import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                    datefmt="%H:%M:%S")

from tools.workflow_tools import sast_scan  # noqa: E402
from tools.storage import StorageManager     # noqa: E402
from tools.recon_artifacts import write_target_artifacts  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Android SAST on decompiled sources")
    ap.add_argument("-Jadx", "--jadx", required=True,
                    help="jadx output dir (contains sources/ + manifest)")
    ap.add_argument("-Target", "--target", type=int, default=0,
                    help="target id to persist findings + refresh artifacts")
    ap.add_argument("-Top", "--top", type=int, default=25,
                    help="how many findings to print (default 25)")
    args = ap.parse_args()

    storage = None
    tid = args.target or None
    if tid:
        storage = StorageManager("workspace").init()

    try:
        result = sast_scan(input=args.jadx, _storage=storage, _target_id=tid)
        summary = result["summary"]
        print(json.dumps(summary, indent=2, ensure_ascii=False))

        # Grouped, readable output: up to 3 findings per rule per severity.
        groups: dict[tuple, list] = {}
        for f in result["findings"]:
            groups.setdefault((f["severity"], f["rule"]), []).append(f)
        print(f"\n=== FINDINGS BY SEVERITY / RULE "
              f"({len(result['findings'])} total) ===")
        for sev in ("critical", "high", "medium", "low", "info"):
            rows = [(rule, items) for (s, rule), items in groups.items()
                    if s == sev]
            if not rows:
                continue
            print(f"\n--- {sev.upper()} ---")
            for rule, items in sorted(rows, key=lambda kv: -len(kv[1])):
                print(f"  [{rule}] x{len(items)}")
                for f in items[:args.top]:
                    where = f["file"]
                    if where.endswith("AndroidManifest.xml"):
                        nm = ""
                        import re as _re
                        m = _re.search(r"android:name=\"([^\"]+)\"", f["snippet"])
                        if m:
                            nm = f" [{m.group(1)}]"
                        print(f"      - manifest:{f['line']}{nm}")
                    else:
                        print(f"      - {where}:{f['line']}"
                              f"  {f['title']}")
                if len(items) > args.top:
                    print(f"      ... +{len(items) - args.top} more")

        if tid:
            art = write_target_artifacts(tid, storage=storage)
            print(f"\n=== ARTIFACTS ===\nINDEX: {art.get('index_md')}")
            if art.get("sast_doc"):
                print(f"SAST : {art['sast_doc']} ({art.get('sast_count')} findings)")
        return 0
    finally:
        if storage:
            storage.close()


if __name__ == "__main__":
    sys.exit(main())
