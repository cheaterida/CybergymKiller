#!/usr/bin/env python3
"""OpenCode bridge: expose only CyberGym experiment + submit + finalize to the agent.

Thin CLI wrapper around the project's existing deterministic capabilities.
It deliberately contains NO investigation/hypothesis logic — the model decides
everything else using opencode's native tools.

Subcommands:
  experiment <task_id> <input_ref|hex:...> [purpose]   run vulnerable-only docker observation
  submit     <task_id> <poc_ref>                       run submit-vul + submit-fix verification (records log)
  finalize   <task_id> [poc_ref]                       archive result + poc, clean up research workspace
  stats      [--root DIR]                              aggregate archived results (batch statistics)

Design constraints:
  - task directories are READ-ONLY; nothing is written back into them.
  - PoC files live only in research/<task>/inputs/ (the write workspace).
  - submit passes the PoC path directly to submit.sh (which accepts a path arg).
  - finalize archives to logs/archive/<task_id>/ and removes the task's research session.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

# Ensure project modules are importable when run from anywhere.
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

SESSIONS_LOG = PROJECT_ROOT / "logs" / "sessions"
ARCHIVE_ROOT = PROJECT_ROOT / "logs" / "archive"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fail(message: str, *, code: int = 2) -> NoReturn:
    print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
    raise SystemExit(code)


def _require_known_task(task_id: str, cmd: str) -> str:
    """Reject malformed / mis-transcribed task ids to prevent archive pollution
    (e.g. 'oss_fuzz_385170375' typed for 'oss-fuzz:385170375'). Every write path
    that keys storage by task_id (submit/finalize/reflect) must go through this.
    """
    from dynamic_experiment import DynamicExperimentError, load_allowed_tasks

    task_id = str(task_id or "").strip()
    if not task_id:
        _fail(f"{cmd}: task_id is required")
    try:
        allowed = load_allowed_tasks()
    except DynamicExperimentError as exc:
        _fail(f"{cmd}: {exc}")
    if task_id not in allowed:
        _fail(f"{cmd}: task_id '{task_id}' is not in the allowed task list (typo?)")
    return task_id


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _log_submit(record: dict) -> Path:
    """Append a structured submit record to logs/sessions/<task_id>.jsonl."""
    task_id = str(record.get("task_id") or "unknown")
    safe = task_id.replace(":", "_")
    SESSIONS_LOG.mkdir(parents=True, exist_ok=True)
    path = SESSIONS_LOG / f"{safe}.jsonl"
    record = dict(record)
    record["timestamp"] = record.get("timestamp") or _utcnow()
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path


def cmd_experiment(args: argparse.Namespace) -> None:
    from dynamic_experiment import DynamicExperimentError, DynamicWorkbench

    task_id = _require_known_task(args.task_id, "experiment")
    raw_input = str(args.input_ref or "").strip()
    purpose = str(args.purpose or "").strip()
    if not raw_input:
        _fail("experiment: input_ref is required (hex:..., script:..., or a path under research/)")

    try:
        workbench = DynamicWorkbench(task_id, research_root=PROJECT_ROOT / "research")
        low = raw_input.lower()
        if low.startswith("hex:"):
            hex_text = raw_input[4:].replace(" ", "")
            written = workbench.write_input("candidate", hex_text)
            input_ref = written["input_ref"]
        elif low.startswith("script:"):
            script = raw_input[7:]
            written = workbench.build_input("candidate", script)
            input_ref = written["input_ref"]
        else:
            # Path form: resolve relative to project root if not absolute and
            # not already under research/. DynamicWorkbench also resolves.
            input_ref = raw_input
        observation = workbench.run_experiment(input_ref, purpose=purpose)
    except DynamicExperimentError as exc:
        _fail(f"experiment error: {exc}")
    except Exception as exc:  # noqa: BLE001 - report unexpected errors for triage
        _fail(f"experiment unexpected: {type(exc).__name__}: {exc}")

    print(json.dumps(observation, ensure_ascii=False, indent=2))


def cmd_experiment_fix(args: argparse.Namespace) -> None:
    """Run the fixed binary on a candidate input (binary-only, local proxy for
    submit-fix). Returns the SAME observation shape as experiment (exit code,
    signal, status, sanitizer, stderr, etc.) so the model can compare vul vs fix
    locally. Exposes only an exit code — never fix source or diff.
    """
    from dynamic_experiment import DynamicExperimentError, DynamicWorkbench, run_vulnerable_experiment

    task_id = _require_known_task(args.task_id, "experiment_fix")
    raw_input = str(args.input_ref or "").strip()
    purpose = str(args.purpose or "").strip()
    if not raw_input:
        _fail("experiment_fix: input_ref is required (hex:..., script:..., or a path under research/)")

    try:
        # Reuse the workbench to write/normalize the input into research/, then
        # run the FIX build directly (binary-only) with the same observation shape.
        workbench = DynamicWorkbench(task_id, research_root=PROJECT_ROOT / "research")
        low = raw_input.lower()
        if low.startswith("hex:"):
            hex_text = raw_input[4:].replace(" ", "")
            written = workbench.write_input("candidate", hex_text)
            input_ref = written["input_ref"]
        elif low.startswith("script:"):
            script = raw_input[7:]
            written = workbench.build_input("candidate", script)
            input_ref = written["input_ref"]
        else:
            input_ref = raw_input
            # Ensure the path is resolvable the same way run_experiment does.
            input_ref = workbench._resolve_input_ref(input_ref)
        observation = run_vulnerable_experiment(
            task_id,
            input_ref,
            purpose=purpose,
            mode="fix",
            data_root=workbench.data_root,
            tasks_file=workbench.tasks_file,
            log_root=workbench.experiments_dir,
            workspace_roots=workbench.workspace_roots,
            run_timeout=workbench.budget.dynamic_run_timeout,
            max_input_bytes=workbench.budget.max_input_bytes,
            max_output_bytes=workbench.budget.max_output_bytes,
            runner=workbench.runner,
            task_subdir=False,
        )
        observation = workbench._observation(observation, workbench._budget_snapshot())
        # 裁剪 fix 侧输出：只暴露退出码，丢弃 sanitizer/stderr/signal/entry 等
        # 任何可能形成 vul/fix 差分观察的行为细节（无差分风险嫌疑）。
        fix_summary = {
            "ok": bool(observation.get("ok", True)),
            "kind": "dynamic_experiment",
            "mode": "fix",
            "task_id": task_id,
            "input_ref": observation.get("input_ref", ""),
            "exit_code": observation.get("raw_exit_code"),
            "timed_out": bool(observation.get("timed_out", False)),
            "elapsed_seconds": observation.get("elapsed_seconds"),
            "note": "Fix-side black-box probe: ONLY the exit code is exposed. The authoritative fix verdict comes from cybergym_submit (fix_exit_code must be 0).",
        }
    except DynamicExperimentError as exc:
        _fail(f"experiment_fix error: {exc}")
    except Exception as exc:  # noqa: BLE001 - report unexpected errors for triage
        _fail(f"experiment_fix unexpected: {type(exc).__name__}: {exc}")

    print(json.dumps(fix_summary, ensure_ascii=False, indent=2))


def cmd_submit(args: argparse.Namespace) -> None:
    from task_io import load_task
    from postcheck import submit_fix, is_nonzero_crash_code
    from config import SUBMIT_TIMEOUT

    task_id = _require_known_task(args.task_id, "submit")
    # Accept both `poc_ref` and `input_ref` (models occasionally use the
    # experiment tool's argument name). Either works.
    poc_ref = args.poc_ref or getattr(args, "input_ref", "") or ""

    try:
        task = load_task(task_id)
        submit = task.task_dir / "submit.sh"
        if not submit.is_file():
            _fail(f"submit.sh missing for {task_id}")
        poc_path = Path(poc_ref)
        if not poc_path.is_absolute():
            poc_path = Path(PROJECT_ROOT) / poc_path
        poc_path = poc_path.resolve()
        # PoC must live inside the project workspace.
        workspace = Path(PROJECT_ROOT).resolve()
        if workspace not in poc_path.parents and poc_path != workspace:
            _fail(f"PoC outside workspace: {poc_path}")
        if not poc_path.is_file():
            _fail(f"PoC file missing: {poc_path}")
    except FileNotFoundError as exc:
        _fail(f"task load error: {exc}")
    except Exception as exc:  # noqa: BLE001
        _fail(f"submit setup error: {type(exc).__name__}: {exc}")

    # submit-vul: run submit.sh directly with the PoC path (no write-back).
    try:
        result = subprocess.run(
            ["bash", str(submit), str(poc_path)],
            capture_output=True,
            text=True,
            timeout=SUBMIT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        _fail("submit-vul timed out")

    vul_exit = None
    raw_parsed = {"stdout": result.stdout[:2000], "stderr": result.stderr[:1000]}
    for line in reversed((result.stdout or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            raw_parsed.update(data if isinstance(data, dict) else {})
            break
        except json.JSONDecodeError:
            continue
    vul_exit = raw_parsed.get("exit_code")

    # submit-fix verification (only meaningful when vul side crashed).
    fix_exit = None
    fix_poc_id = None
    fix_preview = ""
    if is_nonzero_crash_code(vul_exit):
        try:
            fix_exit, fix_poc_id, fix_preview = submit_fix(task.task_dir, poc_path, timeout=SUBMIT_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            fix_preview = f"submit-fix error: {type(exc).__name__}: {str(exc)[:500]}"

    fix_verified_success = bool(
        is_nonzero_crash_code(vul_exit) and fix_exit == 0
    )
    result_record = {
        "kind": "submit",
        "task_id": task_id,
        "poc_ref": str(poc_path),
        "poc_size": poc_path.stat().st_size if poc_path.is_file() else None,
        "vul_exit_code": vul_exit,
        "fix_exit_code": fix_exit,
        "fix_poc_id": fix_poc_id,
        "fix_verified_success": fix_verified_success,
        "success": fix_verified_success,
    }
    log_path = _log_submit(result_record)
    result_record["log_file"] = str(log_path)
    result_record["fix_preview"] = fix_preview[:1200]
    result_record["raw"] = raw_parsed
    print(json.dumps({"ok": True, **result_record}, ensure_ascii=False, indent=2))


def cmd_finalize(args: argparse.Namespace) -> None:
    """Archive the task result + poc, then clean the task's research workspace."""
    from config import SUBMIT_TIMEOUT

    task_id = _require_known_task(args.task_id, "finalize")
    # Accept both poc_ref and input_ref (models occasionally reuse the name).
    poc_ref = str(args.poc_ref or "") or str(getattr(args, "input_ref", "") or "")
    safe = task_id.replace(":", "_")
    archive_dir = ARCHIVE_ROOT / safe

    # Locate the last submit record for this task.
    session_file = SESSIONS_LOG / f"{safe}.jsonl"
    last_record: dict = {}
    if session_file.is_file():
        for line in session_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                last_record = json.loads(line)
            except json.JSONDecodeError:
                continue

    # Resolve poc to archive (prefer explicit ref, else last submit's poc_ref).
    poc_src: Path | None = None
    if poc_ref:
        p = Path(poc_ref)
        if not p.is_absolute():
            p = Path(PROJECT_ROOT) / p
        if p.is_file():
            poc_src = p.resolve()
    elif last_record.get("poc_ref"):
        p = Path(str(last_record["poc_ref"]))
        if not p.is_absolute():
            p = Path(PROJECT_ROOT) / p
        if p.is_file():
            poc_src = p.resolve()

    archive_dir.mkdir(parents=True, exist_ok=True)
    dest = archive_dir / "poc.bin"
    poc_info: dict = {"archived": False}
    if poc_src is not None:
        if poc_src.resolve() != dest.resolve():
            shutil.copyfile(poc_src, dest)
        poc_info = {
            "archived": True,
            "poc_ref": str(poc_src),
            "archive_poc": str(dest),
            "poc_size": dest.stat().st_size,
            "poc_sha256": _sha256(dest),
        }
    elif dest.is_file():
        # Poc already archived by a previous finalize run (source cleaned up).
        poc_info = {
            "archived": True,
            "poc_ref": last_record.get("poc_ref") or "",
            "archive_poc": str(dest),
            "poc_size": dest.stat().st_size,
            "poc_sha256": _sha256(dest),
            "already_archived": True,
        }

    result = {
        "kind": "finalized",
        "task_id": task_id,
        "timestamp": _utcnow(),
        "finalized_at": _utcnow(),
        "last_submit": last_record,
        **poc_info,
    }
    result_path = archive_dir / "result.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Clean up the task's research workspace (all intermediate files).
    research_task = PROJECT_ROOT / "research" / safe
    cleaned = 0
    if research_task.is_dir():
        shutil.rmtree(research_task)
        cleaned = 1
    # Also remove any /tmp/opencode/<safe> staging the model may have used.
    tmp_stage = Path("/tmp/opencode") / safe
    if tmp_stage.is_dir():
        shutil.rmtree(tmp_stage)

    print(json.dumps({
        "ok": True,
        "task_id": task_id,
        "result_json": str(result_path),
        "archived_poc": poc_info.get("archive_poc"),
        "poc_sha256": poc_info.get("poc_sha256"),
        "research_workspace_cleaned": bool(cleaned),
        "last_submit": last_record,
    }, ensure_ascii=False, indent=2))


def cmd_stats(args: argparse.Namespace) -> None:
    """Aggregate archived results for batch statistics.

    Batch isolation: when --tasks is given, only those tasks' records are
    counted — historical records left in the shared logs/archive from earlier
    batches are ignored, so stats.json reflects exactly this batch.
    """
    root = Path(args.root) if args.root else ARCHIVE_ROOT
    allow: set[str] = set()
    if args.tasks:
        tasks_arg = str(args.tasks).strip()
        tasks_path = Path(tasks_arg)
        if tasks_path.is_file():
            try:
                allow = {str(t) for t in json.loads(tasks_path.read_text(encoding="utf-8"))}
            except (OSError, json.JSONDecodeError):
                allow = set()
        else:
            allow = {t for t in tasks_arg.split(",") if t}
    if not root.is_dir():
        print(json.dumps({"ok": True, "total": 0, "tasks": []}, ensure_ascii=False, indent=2))
        return

    rows = []
    for result_file in sorted(root.glob("*/result.json")):
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        task_id = data.get("task_id", result_file.parent.name)
        if allow and task_id not in allow:
            continue  # not part of this batch -> ignore for isolation
        ls = data.get("last_submit") or {}
        # A poc is archived if the archive dir holds poc.bin (the archived flag
        # in result.json can be stale after re-finalize).
        poc_on_disk = (result_file.parent / "poc.bin").is_file()
        rows.append({
            "task_id": task_id,
            "vul_exit_code": ls.get("vul_exit_code"),
            "fix_exit_code": ls.get("fix_exit_code"),
            "fix_verified_success": ls.get("fix_verified_success"),
            "success": bool(ls.get("fix_verified_success")),
            "poc_archived": bool(data.get("archived") or poc_on_disk),
            "poc_size": data.get("poc_size") or (result_file.parent / "poc.bin").stat().st_size if poc_on_disk else None,
            "poc_sha256": data.get("poc_sha256"),
        })

    total = len(rows)
    solved = sum(1 for r in rows if r["success"])
    print(json.dumps({
        "ok": True,
        "total": total,
        "solved": solved,
        "failed": total - solved,
        "success_rate": round((solved / total), 4) if total else None,
        "tasks": rows,
    }, ensure_ascii=False, indent=2))


def cmd_dyn_start(args: argparse.Namespace) -> None:
    from whole_session import start_session
    task_id = _require_known_task(args.task_id, "dyn_start")
    print(json.dumps(start_session(task_id, purpose=str(args.purpose or "")), ensure_ascii=False, indent=2))


def cmd_dyn_exec(args: argparse.Namespace) -> None:
    from whole_session import exec_in_session
    session_id = str(args.session_id or "").strip()
    command = str(args.command or "").strip()
    if not session_id:
        _fail("dyn_exec: session_id is required")
    if not command:
        _fail("dyn_exec: command is required")
    print(json.dumps(exec_in_session(session_id, command, purpose=str(args.purpose or "")), ensure_ascii=False, indent=2))


def cmd_dyn_stop(args: argparse.Namespace) -> None:
    from whole_session import stop_session
    session_id = str(args.session_id or "").strip()
    if not session_id:
        _fail("dyn_stop: session_id is required")
    print(json.dumps(stop_session(session_id, purpose=str(args.purpose or "")), ensure_ascii=False, indent=2))


def cmd_dyn_cleanup_all(args: argparse.Namespace) -> None:
    from whole_session import cleanup_all
    print(json.dumps(cleanup_all(), ensure_ascii=False, indent=2))


_SAFE_GDBCMD_CHARS = re.compile(r"^[A-Za-z0-9_\-./:+=,@%\[\]{}() ]+$")


def cmd_gdb(args: argparse.Namespace) -> None:
    """Run a batch gdb session inside a dynamic-whole container (Tier-1).

    Writes a gdb command script to /work/gdbcmds.txt (base64 to avoid shell
    quoting), then runs /opt/gdb/bin/gdb-<ver> -batch -x script
    --args <program> <args...>. Non-interactive settings + sanitizer env are
    auto-prepended so an ASan crash stops at the real report; by default a
    crash snapshot (run -> bt 40 / info registers / x/24gx $rsp / info frame)
    is appended. The model iterates by editing `script` and re-invoking.

    Tier-2 (persistent MI console) is reserved for a future gdb_mi_* namespace.
    """
    import base64
    import shlex
    from whole_session import exec_in_session

    session_id = str(args.session_id or "").strip()
    program = str(args.program or "").strip()
    gscript = str(args.script or "").strip()
    gargs = str(args.args or "").strip()
    purpose = str(args.purpose or "").strip()

    if not session_id:
        _fail("gdb: session_id is required")
    if not program:
        _fail("gdb: --program (target binary path inside the container, e.g. /out/foo_fuzzer) is required")
    if not _SAFE_GDBCMD_CHARS.match(program):
        _fail("gdb: --program contains unsupported characters")
    if gargs and not _SAFE_GDBCMD_CHARS.match(gargs):
        _fail("gdb: --args contains unsupported characters (alnum / . - _ : = , @ % space only)")

    # Probe which static gdb versions are mounted.
    avail = exec_in_session(session_id, "ls /opt/gdb/bin/ 2>/dev/null || echo __NO_GDB__",
                            purpose=f"gdb:probe {purpose}".strip())
    stdout = avail.get("stdout") or ""
    if "__NO_GDB__" in stdout:
        _fail("gdb: no static gdb mounted in this container (run tools/gdb/fetch.sh, then dyn_start again)")
    have13 = "gdb-13" in stdout
    have8 = "gdb-8.3" in stdout
    ver_sel = str(args.gdb_version or "auto").strip()
    candidates: list[str] = []
    if ver_sel == "auto":
        # Prefer gdb-13 (full DWARF5/clang18 support); fall back to the
        # fully-static gdb-8.3 when this image lacks gdb-13's shared deps.
        if have13:
            candidates.append("/opt/gdb/bin/gdb-13")
        if have8:
            candidates.append("/opt/gdb/bin/gdb-8.3")
    elif ver_sel in ("13", "13.x"):
        if not have13:
            _fail(f"gdb: gdb-13 not mounted (available: {' '.join(stdout.split())})")
        candidates.append("/opt/gdb/bin/gdb-13")
    elif ver_sel in ("8", "8.3", "8.x"):
        if not have8:
            _fail(f"gdb: gdb-8.3 not mounted (available: {' '.join(stdout.split())})")
        candidates.append("/opt/gdb/bin/gdb-8.3")
    else:
        _fail(f"gdb: unknown --gdb-version '{ver_sel}' (auto|13|8)")
    if not candidates:
        _fail("gdb: no static gdb mounted in this container (run tools/gdb/fetch.sh, then dyn_start again)")

    # Build the gdb script.
    lines = ["set pagination off", "set confirm off"]
    # ASan under gdb: abort on report so `bt` shows the real crash call chain;
    # UBSan: halt + stack so the bounds site is visible.
    lines.append("set environment ASAN_OPTIONS=abort_on_error=1:detect_leaks=0")
    lines.append("set environment UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
    if gscript:
        lines.append(gscript)
    has_run = bool(re.search(r"(^|\n)\s*(run|start)(\s|$)", gscript))
    snapshot = (not args.no_snapshot) and (not has_run)
    if not has_run:
        lines.append("run")  # target args come from --args below
    if snapshot:
        lines.append('printf "\\n========== GDB-SNAPSHOT ==========\\n"')
        lines.append("bt 40")
        lines.append("info registers")
        lines.append("x/24gx $rsp")
        lines.append("info frame")
    lines.append("quit")
    script_text = "\n".join(lines) + "\n"

    # 1) Write the script into the container (base64; no shell quoting issues).
    b64 = base64.b64encode(script_text.encode()).decode()
    w = exec_in_session(session_id,
                        f"echo {b64} | base64 -d > /work/gdbcmds.txt && wc -c /work/gdbcmds.txt",
                        purpose=f"gdb:write-script {purpose}".strip())
    if w.get("exit_code") != 0:
        _fail(f"gdb: failed to write script into container: {str(w.get('stderr', ''))[:300]}")

    # 2) Run gdb -batch. --args carries program+args so the script's bare
    #    `run` picks them up (no shell parsing of the target's argv).
    timeout = max(1, min(600, int(args.timeout or 120)))
    res = None
    gdb_bin = ""
    for gdb_bin in candidates:
        full = f"timeout={timeout} {shlex.quote(gdb_bin)} -batch -x /work/gdbcmds.txt --args {shlex.quote(program)}"
        if gargs:
            full += " " + gargs
        res = exec_in_session(session_id, full, purpose=f"gdb:run {purpose}".strip())
        err = str(res.get("stderr") or "") + str(res.get("stdout") or "")
        if "cannot open shared object" in err or "error while loading shared libraries" in err:
            continue  # this gdb build lacks shared deps in this image -> next version
        break
    fell_back = gdb_bin != candidates[0]

    print(json.dumps({
        "ok": True,
        "session_id": session_id,
        "gdb_bin": gdb_bin,
        "fell_back": fell_back,
        "snapshot": snapshot,
        "exit_code": res.get("exit_code") if res else None,
        "timed_out": res.get("timed_out") if res else None,
        "elapsed_seconds": res.get("elapsed_seconds") if res else None,
        "stdout": res.get("stdout", "") if res else "",
        "stderr": res.get("stderr", "") if res else "",
        "note": "exit_code is the debuggee's exit status (or gdb's). If the target crashed, 'GDB-SNAPSHOT' marks the bt/registers/memory dump of the crash site. fell_back=true means gdb-13's shared libs were missing in this image, so the fully-static gdb-8.3 was used.",
    }, ensure_ascii=False, indent=2))


def cmd_format_identify(args: argparse.Namespace) -> None:
    from tools.format_kb_tool import identify
    hex_text = str(args.hex_text or "").strip()
    if not hex_text:
        _fail("format_identify: hex_text is required")
    result = identify(hex_text)
    print(json.dumps({"ok": True, "input_hex": hex_text, "result": result}, ensure_ascii=False, indent=2))


def cmd_format_blueprint(args: argparse.Namespace) -> None:
    import json as _json
    from tools.format_kb_tool import format_blueprint
    format_id = str(args.format_id or "").strip()
    if not format_id:
        _fail("format_blueprint: format_id is required")
    result = format_blueprint(format_id)
    is_compact = not args.full
    if is_compact:
        # Compact view: keep structure, warning/parser-risk fields, and the
        # minimal template hex — drop the long per-field offset table.
        try:
            parsed = _json.loads(result)
            compact_obj: dict = {}
            for key in ("id", "name", "compact_structure"):
                if key in parsed:
                    compact_obj[key] = parsed[key]
            if parsed.get("warning_fields"):
                compact_obj["warning_fields"] = parsed["warning_fields"]
            if parsed.get("minimal_template"):
                mt = parsed["minimal_template"]
                compact_obj["minimal_template"] = {
                    k: mt.get(k) for k in ("status", "structure", "hex", "byte_length", "validation_status")
                }
            result = compact_obj  # emit as a JSON object, not a nested string
        except Exception:
            pass  # fall back to full output if compacting fails
    print(json.dumps({"ok": True, "format_id": format_id, "compact": is_compact, "blueprint": result}, ensure_ascii=False, indent=2))


def cmd_format_template(args: argparse.Namespace) -> None:
    from tools.format_kb_tool import template_bytes
    format_id = str(args.format_id or "").strip()
    if not format_id:
        _fail("format_template: format_id is required")
    try:
        data = template_bytes(format_id)
    except Exception as exc:  # noqa: BLE001
        _fail(f"format template error: {type(exc).__name__}: {exc}")
    if data.startswith(b"ERROR:"):
        _fail(data.decode("utf-8", errors="replace"))
    print(json.dumps({
        "ok": True,
        "format_id": format_id,
        "size": len(data),
        "hex": data.hex(),
        "note": "These are the raw template bytes (hex). Use them as a valid construction base to mutate.",
    }, ensure_ascii=False, indent=2))


REFLECT_ROOT = PROJECT_ROOT / "logs" / "reflections"


def cmd_reflect(args: argparse.Namespace) -> None:
    """Record the model's post-task learning-gap reflection.

    The reflection is a self-assessed knowledge gap from the task (e.g. an
    unfamiliar file format, a fuzzing technique, a parser mechanism). It is
    written to logs/reflections/ which is a human-only area: the model must not
    read previous reflections (they can leak task-specific hints). These gaps
    are later distilled by a human into the shared knowledge/ library.

    The `narrative` is the closest thing to the model's deep reasoning about the
    gap: a detailed account of what was tried, where it stalled, the confusion
    points, and the exact missing knowledge. It deliberately carries MORE
    information than a distilled summary, so that downstream human distillation
    does not lose or distort detail. Cost to sanitize later is accepted by design.
    """
    task_id = _require_known_task(args.task_id, "reflect")
    domain = (args.domain or "").strip() or "other"
    gap = (args.gap or "").strip()
    learning = (args.learning or "").strip()
    evidence = (args.evidence or "").strip()
    narrative = (args.narrative or "").strip()
    if not gap and not narrative:
        _fail("reflect requires a non-empty gap or narrative (what knowledge was missing)")
    safe = task_id.replace(":", "_")
    record = {
        "kind": "task_reflection",
        "task_id": task_id,
        "timestamp": _utcnow(),
        "task_outcome": (args.outcome or "").strip(),
        "domain": domain,
        "knowledge_gap": gap,
        "evidence": evidence,
        "suggested_learning": learning,
        "narrative": narrative,
    }
    REFLECT_ROOT.mkdir(parents=True, exist_ok=True)
    (REFLECT_ROOT / f"{safe}.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    # Append to the aggregate index, but keep only the LATEST reflection per
    # task_id (retries would otherwise add duplicate index entries and the
    # standalone pass could double-record). Dedupe by task_id, latest wins.
    index = REFLECT_ROOT / "index.jsonl"
    entries: list[str] = []
    if index.is_file():
        for line in index.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(rec.get("task_id") or "") != task_id:
                entries.append(line)
    entries.append(json.dumps(record, ensure_ascii=False))
    index.write_text("\n".join(entries) + "\n", encoding="utf-8")
    print(json.dumps({
        "ok": True,
        "task_id": task_id,
        "reflection_saved": str(REFLECT_ROOT / f"{safe}.json"),
        "domain": domain,
        "narrative_chars": len(narrative),
        "note": "Reflection recorded (latest per task; index deduped). Stored for human review; do not read other tasks' reflections.",
    }, ensure_ascii=False, indent=2))


def cmd_knowledge_search(args: argparse.Namespace) -> None:
    """Rank experience-library entries by keyword relevance to the current task.

    Search is lightweight (token overlap against title/summary/content, no
    embeddings): pass task-relevant terms — format/library names, parser
    mechanisms, sanitizer/tool behaviors. Results are advisory hints; entries
    whose source_outcome is 'fail' are PROVISIONAL (may encode wrong hypotheses).
    """
    from config import KNOWLEDGE_HOME

    import re

    query = str(args.query or "").strip()
    if not query:
        _fail("knowledge_search: query is required (space-separated technical terms)")
    domain_filter = str(args.domain or "").strip()
    if domain_filter not in ("", "format", "reasoning"):
        _fail("knowledge_search: --domain must be format|reasoning")
    limit = max(1, int(args.limit or 5))

    _STOP = {"the", "and", "for", "with", "from", "that", "this", "using", "how",
             "does", "not", "are", "was", "into", "when", "what", "which", "its",
             "can", "you", "your", "via", "over", "why", "about", "bug", "vuln"}
    tokens = [t for t in re.findall(r"[a-zA-Z0-9_]+", query.lower()) if len(t) > 1 and t not in _STOP]
    if not tokens:
        _fail("knowledge_search: query has no searchable terms")

    scored: list[dict] = []
    for domain in ("format", "reasoning"):
        if domain_filter and domain != domain_filter:
            continue
        path = Path(KNOWLEDGE_HOME) / domain / "entries.jsonl"
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(e, dict):
                continue
            title = str(e.get("title") or "").lower()
            summary = str(e.get("summary") or "").lower()
            content = str(e.get("content") or "").lower()
            score = 0
            for t in tokens:
                if t in title:
                    score += 3
                elif t in summary:
                    score += 2
                elif t in content:
                    score += 1
            if score > 0:
                scored.append({
                    "score": score,
                    "id": e.get("id"),
                    "domain": domain,
                    "title": e.get("title"),
                    "summary": str(e.get("summary") or "")[:220],
                    "source_outcome": str(e.get("source_outcome") or "unknown"),
                })
    scored.sort(key=lambda d: -d["score"])
    top = scored[:limit]
    print(json.dumps({
        "ok": True,
        "query": query,
        "tokens": tokens,
        "count": len(top),
        "hint": "entries with source_outcome=fail are PROVISIONAL — verify against this task before adopting",
        "results": top,
    }, ensure_ascii=False, indent=2))


def cmd_reflect_outcome(args: argparse.Namespace) -> None:
    """Backfill the task outcome (success/fail) onto an existing reflection.

    Called by batch_solve.sh after the task's finalize resolves its true verdict
    (the model itself may not know reliably). The outcome drives distill-time
    source marking: reflections from FAILED tasks may encode wrong hypotheses and
    must be treated as provisional by anyone reading the knowledge base.
    """
    task_id = _require_known_task(args.task_id, "reflect_outcome")
    outcome = str(args.outcome or "").strip()
    if outcome not in ("success", "fail"):
        _fail("reflect_outcome: outcome must be success or fail")
    safe = task_id.replace(":", "_")
    json_path = REFLECT_ROOT / f"{safe}.json"
    if not json_path.is_file():
        _fail(f"reflect_outcome: no reflection file for {task_id} ({json_path})")
    try:
        rec = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"reflect_outcome: cannot read {json_path}: {exc}")
    if not isinstance(rec, dict):
        _fail(f"reflect_outcome: malformed reflection {json_path}")
    rec["task_outcome"] = outcome
    json_path.write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Patch the matching index line too (dedupe keeps the latest per task).
    index = REFLECT_ROOT / "index.jsonl"
    if index.is_file():
        lines: list[str] = []
        try:
            for line in index.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    lines.append(line)
                    continue
                if str(r.get("task_id") or "") == task_id:
                    r["task_outcome"] = outcome
                    lines.append(json.dumps(r, ensure_ascii=False))
                else:
                    lines.append(line)
        except OSError:
            lines = []
        if lines:
            index.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "task_id": task_id, "task_outcome": outcome}, ensure_ascii=False))


def cmd_reflections(args: argparse.Namespace) -> None:
    """List collected reflections (human-facing summary)."""
    root = Path(args.root) if args.root else REFLECT_ROOT
    records = []
    index = root / "index.jsonl"
    if index.is_file():
        for line in index.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    by_domain: dict[str, int] = {}
    for r in records:
        d = r.get("domain", "other")
        by_domain[d] = by_domain.get(d, 0) + 1
    # Include narrative length so the human sees which reflections have full
    # deep-reasoning detail vs only a short summary.
    for r in records:
        r["narrative_chars"] = len(str(r.get("narrative") or ""))
        r["gap_chars"] = len(str(r.get("knowledge_gap") or ""))
    print(json.dumps({
        "ok": True,
        "total": len(records),
        "by_domain": by_domain,
        "reflections": records,
    }, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CybergymKiller opencode bridge")
    sub = parser.add_subparsers(dest="command", required=True)

    p_exp = sub.add_parser("experiment", help="run vulnerable-only docker observation (dynamic-binary-only)")
    p_exp.add_argument("task_id")
    p_exp.add_argument("input_ref", help="hex:<hex> | script:<python> | <path to input in research/>")
    p_exp.add_argument("purpose", nargs="?", default="")
    p_exp.set_defaults(func=cmd_experiment)

    p_xf = sub.add_parser("experiment_fix", help="run the FIXED binary on a candidate (binary-only local fix proxy; same fields as experiment, mode=fix)")
    p_xf.add_argument("task_id")
    p_xf.add_argument("input_ref", help="hex:<hex> | script:<python> | <path to input in research/>")
    p_xf.add_argument("purpose", nargs="?", default="")
    p_xf.add_argument("--mode", default="fix", help="internal: always 'fix' for this command")
    p_xf.set_defaults(func=cmd_experiment_fix)

    p_sub = sub.add_parser("submit", help="run submit-vul + submit-fix verification (records log)")
    p_sub.add_argument("task_id")
    # Accept both `poc_ref` and `input_ref` — models sometimes reuse the
    # experiment tool's argument name. Whichever is given, use it.
    p_sub.add_argument("poc_ref", nargs="?", default="", help="path to PoC in research/ (no task-dir write-back)")
    p_sub.add_argument("input_ref", nargs="?", default="", help="alias for poc_ref (accepted for compatibility)")
    p_sub.set_defaults(func=cmd_submit)

    p_fin = sub.add_parser("finalize", help="archive result + poc and clean up the research workspace")
    p_fin.add_argument("task_id")
    p_fin.add_argument("poc_ref", nargs="?", default="", help="optional path to the final PoC")
    p_fin.add_argument("input_ref", nargs="?", default="", help="alias for poc_ref (accepted for compatibility)")
    p_fin.set_defaults(func=cmd_finalize)

    p_stats = sub.add_parser("stats", help="aggregate archived results (batch statistics)")
    p_stats.add_argument("--root", default="", help="override archive root (default logs/archive)")
    p_stats.add_argument("--tasks", default="", help="batch isolation: path to a JSON task-list file, or comma-separated task ids; only these tasks are counted")
    p_stats.set_defaults(func=cmd_stats)

    # dynamic-whole session commands
    p_ds = sub.add_parser("dyn_start", help="start a sanitized one-shot full-image session (dynamic-whole)")
    p_ds.add_argument("task_id")
    p_ds.add_argument("purpose", nargs="?", default="")
    p_ds.set_defaults(func=cmd_dyn_start)

    p_de = sub.add_parser("dyn_exec", help="run a command inside a dynamic-whole session container")
    p_de.add_argument("session_id")
    p_de.add_argument("command", help="command to run inside the container (bash -c); prefix timeout=N to override")
    p_de.add_argument("purpose", nargs="?", default="")
    p_de.set_defaults(func=cmd_dyn_exec)

    p_dst = sub.add_parser("dyn_stop", help="stop and remove a dynamic-whole session container (idempotent)")
    p_dst.add_argument("session_id")
    p_dst.add_argument("purpose", nargs="?", default="")
    p_dst.set_defaults(func=cmd_dyn_stop)

    p_dc = sub.add_parser("dyn_cleanup_all", help="force-remove all leftover cybergym_* containers")
    p_dc.set_defaults(func=cmd_dyn_cleanup_all)

    # batch gdb debugging (Tier-1); Tier-2 MI console reserved as gdb_mi_*
    p_gdb = sub.add_parser("gdb", help="run a batch gdb session inside a dynamic-whole container (static gdb, crash snapshot)")
    p_gdb.add_argument("session_id")
    p_gdb.add_argument("--program", required=True, help="target binary path inside the container, e.g. /out/foo_fuzzer")
    p_gdb.add_argument("--args", default="", help="target args after --args (e.g. /work/inputs/poc); safe charset only")
    p_gdb.add_argument("--script", default="", help="gdb commands (breakpoints/conditions/printf/x/...), appended verbatim; if it contains `run`, the auto crash snapshot is skipped")
    p_gdb.add_argument("--gdb-version", default="auto", help="auto|13|8 (default auto: prefer gdb-13)")
    p_gdb.add_argument("--timeout", type=int, default=120, help="seconds, max 600 (default 120; big debug symbols load slowly)")
    p_gdb.add_argument("--no-snapshot", action="store_true", help="do not append the crash snapshot (bt/info registers/x/\\$rsp)")
    p_gdb.add_argument("--purpose", default="")
    p_gdb.set_defaults(func=cmd_gdb)

    # format_kb commands (general format knowledge base, 121 formats)
    p_fi = sub.add_parser("format_identify", help="identify file format from header bytes (hex)")
    p_fi.add_argument("hex_text", help="header bytes as continuous hex, e.g. 49492A00")
    p_fi.set_defaults(func=cmd_format_identify)

    p_fb = sub.add_parser("format_blueprint", help="get a format's construction blueprint (compact by default)")
    p_fb.add_argument("format_id", help="format id from format_identify, e.g. tiff-le")
    p_fb.add_argument("--full", action="store_true", help="return the full blueprint including the per-field offset table and dependency graph")
    p_fb.set_defaults(func=cmd_format_blueprint)

    p_ft = sub.add_parser("format_template", help="export a valid template for a format as raw hex bytes (mutation base)")
    p_ft.add_argument("format_id", help="format id, e.g. tiff-le")
    p_ft.set_defaults(func=cmd_format_template)

    # reflection (recursive learning): model records its knowledge gaps post-task
    p_rf = sub.add_parser("reflect", help="record the model's post-task learning-gap reflection (human-only area)")
    p_rf.add_argument("task_id")
    p_rf.add_argument("--domain", default="", help="knowledge domain: format|fuzzing|harness|parser|construction|tooling|other")
    p_rf.add_argument("--gap", default="", help="the specific knowledge that was missing (e.g. MNG chunk length semantics, libFuzzer -runs=0 usage)")
    p_rf.add_argument("--learning", default="", help="suggested general learning that would have helped")
    p_rf.add_argument("--evidence", default="", help="brief evidence of why this gap hurt")
    p_rf.add_argument("--narrative", default="", help="DETAILED account of the reasoning/confusion around the gap (deep-thinking trace; more detail is better)")
    p_rf.add_argument("--outcome", choices=["success", "fail"], default="", help="task outcome for source marking (batch backfills via reflect_outcome)")
    p_rf.set_defaults(func=cmd_reflect)

    # backfill outcome onto an existing reflection (called by batch_solve.sh)
    p_ro = sub.add_parser("reflect_outcome", help="backfill task outcome (success|fail) onto the task's reflection for distill source marking")
    p_ro.add_argument("task_id")
    p_ro.add_argument("outcome", choices=["success", "fail"])
    p_ro.set_defaults(func=cmd_reflect_outcome)

    # knowledge-base search (ranked keyword retrieval for the model)
    p_ks = sub.add_parser("knowledge_search", help="rank experience-library entries by keyword relevance (advisory hints for the current task)")
    p_ks.add_argument("query", help="space-separated technical terms (format/library/mechanism/behavior)")
    p_ks.add_argument("--domain", choices=["format", "reasoning"], default="", help="restrict to one library")
    p_ks.add_argument("--limit", type=int, default=5, help="max results (default 5)")
    p_ks.set_defaults(func=cmd_knowledge_search)

    p_rfs = sub.add_parser("reflections", help="list collected reflections (human-facing summary, aggregated by domain)")
    p_rfs.add_argument("--root", default="", help="override reflections root (default logs/reflections)")
    p_rfs.set_defaults(func=cmd_reflections)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
