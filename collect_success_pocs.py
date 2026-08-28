#!/usr/bin/env python3
"""Collect successful-task PoCs into a per-batch directory for later research.

At batch end this is invoked by batch_solve.sh with the batch dir; for every
task whose latest archived result is success (fix_verified_success == true), it
copies logs/archive/<safe>/poc.bin + result.json into
<out_dir>/<safe>/ and writes a MANIFEST.json summarizing the collection
(task id, poc size/sha256, vul/fix exit codes).
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
ARCHIVE = PROJECT / "logs" / "archive"


def main(argv: list[str]) -> int:
    out_dir = Path(argv[1]) if len(argv) > 1 else PROJECT / "logs" / "successful_pocs"
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "kind": "successful_pocs_collection",
        "source_archive": str(ARCHIVE),
        "count": 0,
        "entries": [],
    }
    if not ARCHIVE.is_dir():
        print(f"collect_success_pocs: no archive dir {ARCHIVE}")
        return 0

    for task_dir in sorted(ARCHIVE.iterdir()):
        if not task_dir.is_dir():
            continue
        rp = task_dir / "result.json"
        if not rp.is_file():
            continue
        try:
            r = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ls = r.get("last_submit") or {}
        if not ls.get("fix_verified_success"):
            continue
        poc = task_dir / "poc.bin"
        if not poc.is_file():
            continue
        safe = task_dir.name
        dst = out_dir / safe
        dst.mkdir(parents=True, exist_ok=True)
        shutil.copy2(poc, dst / "poc.bin")
        shutil.copy2(rp, dst / "result.json")
        manifest["entries"].append({
            "task_id": r.get("task_id"),
            "safe": safe,
            "poc_size": poc.stat().st_size,
            "poc_sha256": hashlib.sha256(poc.read_bytes()).hexdigest(),
            "vul_exit_code": ls.get("vul_exit_code"),
            "fix_exit_code": ls.get("fix_exit_code"),
            "finalized_at": r.get("finalized_at", ""),
        })

    manifest["count"] = len(manifest["entries"])
    (out_dir / "MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"collect_success_pocs: {manifest['count']} successful PoCs -> {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
