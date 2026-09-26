"""CLI runner: execute a workflow YAML from the terminal (PowerShell).

Equivalent to the MCP tool ``workflow_run`` but runnable directly:

    python scripts\\run_workflow.py -Apk D:\\path\\app.apk -Package com.target.app
    python scripts\\run_workflow.py -Workflow flutter_recon -Apk app.apk
    python scripts\\run_workflow.py -Package com.target.app        # no APK (re-run)

Then read results at workspace\\targets\\<package>_<id>\\INDEX.md
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.storage import StorageManager          # noqa: E402
from tools.workflow import WorkflowEngine, WorkflowError  # noqa: E402

WORKFLOW_DIR = ROOT / "workflows"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an Android pentest workflow")
    parser.add_argument("-Workflow", "--workflow", default="default",
                        help="Workflow name without .yaml (default: default; "
                             "also: default_tier_a, flutter_recon)")
    parser.add_argument("-Apk", "--apk", default="",
                        help="Path to the APK file")
    parser.add_argument("-Package", "--package", default="",
                        help="Android package name (default: APK filename stem)")
    parser.add_argument("-Version", "--version", default="",
                        help="App version string (optional)")
    args = parser.parse_args()

    if not args.apk and not args.package:
        parser.error("-Apk or -Package required")

    wf_path = WORKFLOW_DIR / f"{args.workflow}.yaml"
    if not wf_path.exists():
        print(f"ERROR: workflow '{args.workflow}' not found at {wf_path}")
        return 2

    package = args.package or Path(args.apk).stem

    storage = StorageManager("workspace").init()
    try:
        target_id = storage.create_target(package, version_name=args.version)
        if args.apk:
            storage.save_apk(target_id, args.apk, version_name=args.version)

        print(f"=== Workflow '{args.workflow}' -> target {target_id} ({package}) ===")
        engine = WorkflowEngine(storage)
        engine.load(str(wf_path))
        try:
            engine.execute(target_id, args.apk)
        except WorkflowError as e:
            print(f"WORKFLOW FAILED: {e}")
            return 1

        # Summary
        findings = storage.get_findings(target_id)
        def count(table: str) -> int:
            return storage._fetchall(
                f"SELECT COUNT(*) AS c FROM {table} WHERE target_id=?",
                (target_id,))[0]["c"]

        summary = {
            "status": "completed",
            "target_id": target_id,
            "package": package,
            "workflow": args.workflow,
            "findings": len(findings),
            "endpoints": count("endpoints"),
            "secrets": count("secrets"),
            "subdomains": count("subdomains"),
            "by_severity": {
                sev: sum(1 for f in findings if f.get("severity") == sev)
                for sev in ("critical", "high", "medium", "low")
            },
        }
        print(json.dumps(summary, indent=2))

        # Print artifact entry point
        from tools.recon_artifacts import write_target_artifacts
        artifacts = write_target_artifacts(target_id, storage=storage)
        print()
        print(">>> READ RESULTS AT:")
        print(f"    {artifacts.get('index_md')}")
        return 0
    finally:
        storage.close()


if __name__ == "__main__":
    sys.exit(main())
