"""dynamic-whole container session manager.

Provides one-shot, interaction-capable containers from the official full
vulnerable images (n132/arvo:<id>-vul / cybergym/oss-fuzz:<id>-vul). Each
session is created fresh, sanitized (fixed blacklist), admitted to the model,
used via dyn_exec, and torn down on dyn_stop.

Safety invariants (all hard-coded; the model cannot control them):
  - network=none
  - non-privileged, no docker socket, no host volumes except a read-only
    inputs mount (research/<task>/inputs -> /work/inputs)
  - sanitation uses fixed commands only (no model-supplied paths)
  - pristine images are never modified (cleanup happens in the writable layer)

This module is deliberately separate from dynamic_experiment.py (binary-only).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dynamic_experiment import DynamicExperimentError, _safe_task_number, load_allowed_tasks

PROJECT_ROOT = Path(__file__).resolve().parent

# Image family -> image repository. Task number validated by _safe_task_number.
ARVO_REPO = "n132/arvo"
OSS_FUZZ_REPO = "cybergym/oss-fuzz"

DEFAULT_TASKS_FILE = PROJECT_ROOT / "tasks.json"

# Fixed sanitation rules (this iteration): only VCS .git dirs and /tmp/poc.
# Per user decision, .hg/.svn/repo-fix/patch.diff are NOT in scope yet.
VCS_DIR_NAMES = (".git",)
POC_BLACKLIST = ("/tmp/poc",)

# Command timeouts.
EXEC_TIMEOUT_DEFAULT = 60
EXEC_TIMEOUT_MAX = 600
OUTPUT_LIMIT = 20000

SESSION_ROOT = PROJECT_ROOT / "logs" / "sessions"
AUDIT_ROOT = PROJECT_ROOT / "logs" / "session_audit"
# Where the model's inputs live on the host; mounted read-only at /work/inputs.
RESEARCH_ROOT = PROJECT_ROOT / "research"


@dataclass
class SessionInfo:
    session_id: str
    task_id: str
    image: str
    container_id: str
    purpose: str
    created_at: str
    sanitized: bool
    status: str  # running | stopped | destroyed
    exec_count: int = 0


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fail(message: str, code: int = 2):
    print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
    raise SystemExit(code)


def _image_for_task(task_id: str) -> str:
    family, number = _safe_task_number(task_id)
    repo = ARVO_REPO if family == "arvo" else OSS_FUZZ_REPO
    return f"{repo}:{number}-vul"


def _session_dir(session_id: str) -> Path:
    return SESSION_ROOT / session_id


def _run(cmd: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DynamicExperimentError(f"command timed out: {' '.join(cmd[:4])}...") from None


def _docker_exec(container_id: str, command: str, *, timeout: int = EXEC_TIMEOUT_DEFAULT) -> dict[str, Any]:
    """Run a command inside the container. Returns structured result."""
    started = time.monotonic()
    cmd = ["docker", "exec", container_id, "/bin/bash", "-c", command]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {
            "timed_out": True,
            "exit_code": 137,
            "stdout": "",
            "stderr": f"command timed out after {timeout}s",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    stdout = (proc.stdout or "")[:OUTPUT_LIMIT]
    stderr = (proc.stderr or "")[:OUTPUT_LIMIT]
    return {
        "timed_out": False,
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


# ---------------------------------------------------------------------------
# Sanitation
# ---------------------------------------------------------------------------

_SCAN_SCRIPT = r"""
set -e
echo "__VCS__"
find /src -type d \( -name .git \) 2>/dev/null || true
echo "__POC__"
ls -la /tmp/poc 2>/dev/null || true
echo "__END__"
"""


def _scan_container(container_id: str) -> dict[str, Any]:
    """Return vcs_dirs (list) and poc_present (bool)."""
    res = _docker_exec(container_id, _SCAN_SCRIPT, timeout=30)
    out = (res.get("stdout") or "") + (res.get("stderr") or "")
    vcs: list[str] = []
    poc = False
    capture_vcs = False
    for line in out.splitlines():
        line = line.strip()
        if line == "__VCS__":
            capture_vcs = True
            continue
        if line == "__POC__":
            capture_vcs = False
            continue
        if line == "__END__":
            break
        if capture_vcs and line and not line.startswith("__"):
            vcs.append(line)
        if line.startswith("/tmp/poc"):
            poc = True
    return {"vcs_dirs": vcs, "poc_present": poc}


_SANITIZE_SCRIPT = r"""
set -e
find /src -type d -name .git -exec rm -rf {} + 2>/dev/null || true
rm -f /tmp/poc 2>/dev/null || true
"""


def sanitize_container(container_id: str) -> dict[str, Any]:
    """Run fixed sanitation and return the audit manifest."""
    pre = _scan_container(container_id)
    res = _docker_exec(container_id, _SANITIZE_SCRIPT, timeout=120)
    post = _scan_container(container_id)
    clean = (
        not post["vcs_dirs"]
        and not post["poc_present"]
        and res.get("exit_code") == 0
    )
    return {
        "kind": "dyn_whole_sanitation_audit",
        "pre_vcs_dirs": pre["vcs_dirs"],
        "pre_poc_present": pre["poc_present"],
        "post_vcs_dirs": post["vcs_dirs"],
        "post_poc_present": post["poc_present"],
        "sanitize_exit_code": res.get("exit_code"),
        "clean": clean,
        "timestamp": _utcnow(),
    }


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

def start_session(task_id: str, *, purpose: str = "") -> dict[str, Any]:
    allowed = load_allowed_tasks(DEFAULT_TASKS_FILE)
    if task_id not in allowed:
        _fail(f"task not in allowlist: {task_id}")
    image = _image_for_task(task_id)
    safe_task = task_id.replace(":", "_")
    inputs_dir = RESEARCH_ROOT / safe_task / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    session_id = f"dyn_{int(time.time() * 1000)}"
    # One-shot container: no --rm (we manage cleanup explicitly).
    create_cmd = [
        "docker", "create",
        "--network", "none",
        "--name", f"cybergym_{safe_task}_{session_id}",
        "--volume", f"{inputs_dir.resolve()}:/work/inputs:ro",
        "--workdir", "/work",
        image,
        "sleep", "infinity",
    ]
    proc = _run(create_cmd, timeout=60)
    if proc.returncode != 0:
        _fail(f"docker create failed: {(proc.stderr or '')[:500]}")
    container_id = (proc.stdout or "").strip()

    start_proc = _run(["docker", "start", container_id], timeout=60)
    if start_proc.returncode != 0:
        _run(["docker", "rm", "-f", container_id], timeout=30)
        _fail(f"docker start failed: {(start_proc.stderr or '')[:500]}")

    audit = sanitize_container(container_id)
    if not audit["clean"]:
        _run(["docker", "rm", "-f", container_id], timeout=30)
        _fail(f"sanitation failed (clean=false); container destroyed: {json.dumps(audit)}")

    session_dir = _session_dir(session_id)
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "sanitation_audit.json").write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")
    (session_dir / "session_info.json").write_text(json.dumps({
        "session_id": session_id,
        "task_id": task_id,
        "image": image,
        "container_id": container_id,
        "purpose": purpose,
        "created_at": _utcnow(),
        "status": "running",
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "ok": True,
        "session_id": session_id,
        "task_id": task_id,
        "image": image,
        "container_id": container_id,
        "sanitized": True,
        "sanitation_audit": audit,
        "work": "/work",
        "inputs_mount": f"{inputs_dir} (ro) -> /work/inputs",
    }


def _load_session(session_id: str) -> dict[str, Any]:
    info_path = _session_dir(session_id) / "session_info.json"
    if not info_path.is_file():
        _fail(f"session not found: {session_id}")
    try:
        return json.loads(info_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _fail(f"session info unreadable: {session_id}")


def exec_in_session(session_id: str, command: str, *, purpose: str = "") -> dict[str, Any]:
    info = _load_session(session_id)
    container_id = info["container_id"]
    timeout = EXEC_TIMEOUT_DEFAULT
    # Allow an explicit leading timeout token: "timeout=120 <command>"
    m = re.match(r"^timeout=(\d+)\s+(.*)$", command, re.S)
    if m:
        timeout = max(1, min(EXEC_TIMEOUT_MAX, int(m.group(1))))
        command = m.group(2)
    res = _docker_exec(container_id, command, timeout=timeout)
    # Record action log.
    session_dir = _session_dir(session_id)
    log_path = session_dir / "actions.jsonl"
    record = {
        "session_id": session_id,
        "purpose": purpose,
        "command_digest": command[:200],
        "exit_code": res.get("exit_code"),
        "timed_out": res.get("timed_out"),
        "elapsed_seconds": res.get("elapsed_seconds"),
    }
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    return {
        "ok": True,
        "session_id": session_id,
        "exit_code": res.get("exit_code"),
        "timed_out": res.get("timed_out"),
        "stdout": res.get("stdout", ""),
        "stderr": res.get("stderr", ""),
    }


def stop_session(session_id: str, *, purpose: str = "") -> dict[str, Any]:
    """Stop and remove the container. Idempotent; safe if already gone."""
    session_dir = _session_dir(session_id)
    info: dict[str, Any] = {}
    if session_dir.is_dir():
        try:
            info = json.loads((session_dir / "session_info.json").read_text(encoding="utf-8"))
        except Exception:
            info = {}
    container_id = info.get("container_id", "")
    outcome = "not_found"
    if container_id:
        # Best-effort: stop then remove.
        _run(["docker", "stop", "-t", "5", container_id], timeout=30)
        rm_proc = _run(["docker", "rm", "-f", container_id], timeout=30)
        if rm_proc.returncode == 0:
            outcome = "destroyed"
        else:
            # Could already be gone.
            inspect = _run(["docker", "inspect", container_id], timeout=30)
            outcome = "destroyed" if inspect.returncode != 0 else "remove_failed"
    if outcome == "remove_failed":
        _fail(f"failed to remove container {container_id}")
    if session_dir.is_dir():
        final = {
            **info,
            "status": "destroyed",
            "stopped_at": _utcnow(),
            "stop_purpose": purpose,
        }
        (session_dir / "session_final.json").write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "session_id": session_id,
        "outcome": outcome,
        "stopped_at": _utcnow(),
    }


def cleanup_all() -> dict[str, Any]:
    """Scan for leftover cybergym_* containers and force-remove them."""
    proc = _run(["docker", "ps", "-a", "--filter", "name=cybergym_", "--format", "{{.ID}} {{.Names}}"], timeout=30)
    removed: list[str] = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        cid = parts[0]
        name = parts[1] if len(parts) > 1 else ""
        rm = _run(["docker", "rm", "-f", cid], timeout=30)
        if rm.returncode == 0:
            removed.append(name or cid)
    return {"ok": True, "removed_containers": removed, "count": len(removed)}


def list_sessions() -> dict[str, Any]:
    sessions = []
    for d in sorted(SESSION_ROOT.glob("dyn_*")):
        info_path = d / "session_info.json"
        if not info_path.is_file():
            continue
        try:
            info = json.loads(info_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        sessions.append({
            "session_id": info.get("session_id"),
            "task_id": info.get("task_id"),
            "status": info.get("status"),
            "created_at": info.get("created_at"),
        })
    return {"ok": True, "sessions": sessions}
