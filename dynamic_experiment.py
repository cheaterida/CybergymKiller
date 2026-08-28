"""Vulnerable-only experiments against CyberGym binary-only runner data.

This module is deliberately independent from the trial workflow and final
submission path.  It runs only the vulnerable side and returns observations;
it never decides whether a vulnerability was demonstrated.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from config import CYBERGYM_HOME, LOGS_DIR, PROJECT_ROOT


DEFAULT_TASKS_FILE = PROJECT_ROOT / "tasks.json"
DEFAULT_DATA_ROOT = CYBERGYM_HOME / "cybergym-server-data"
DEFAULT_RUNNER_IMAGE = "cybergym/oss-fuzz-base-runner:latest"
DEFAULT_RUN_TIMEOUT = 10
DEFAULT_DOCKER_TIMEOUT = 60
DEFAULT_MAX_INPUT_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 2 * 1024 * 1024

# Model research workspace: inputs and experiment results for the current task
# session live here (distinct from `logs/`, which is the run archive).
RESEARCH_ROOT = PROJECT_ROOT / "research"

# Per-session dynamic experiment budget (one DynamicWorkbench = one task session).
DEFAULT_MAX_EXPERIMENTS_PER_TASK = 8
DEFAULT_MAX_TOTAL_DYNAMIC_SECONDS = 300.0
DEFAULT_STDOUT_STDERR_SUMMARY_BYTES = 4000

_INPUT_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

# Target stderr keywords that suggest an input was rejected at (or very early in)
# parsing, as opposed to accepted and parsed cleanly. Advisory only.
_ENTRY_REJECT_MARKERS = (
    "unsupported", "invalid", "not a valid", "bad magic", "bad header", "invalid header",
    "malformed", "corrupt", "parse error", "unrecognized", "failed to parse", "too short",
    "unknown format", "truncated", "unexpected eof", "magic number",
)


def _entry_hint(stderr: str) -> str:
    """Soft signal on whether the target itself reported an early-rejection error."""
    low = str(stderr or "").lower()
    hits = [marker for marker in _ENTRY_REJECT_MARKERS if marker in low]
    if hits:
        return "likely_rejected_early:" + ",".join(sorted(set(hits))[:3])
    return ""


_EXEC_MS_RE = re.compile(r"in (\d+) ms", re.IGNORECASE)


def _exec_ms(stderr: str) -> int | None:
    """Extract the target-internal execution time from the fuzzer's own output.

    libFuzzer prints "Executed /testcase in N ms"; this is the target-side
    timing signal, unaffected by Docker launch jitter.
    """
    matches = _EXEC_MS_RE.findall(str(stderr or ""))
    if not matches:
        return None
    try:
        return int(matches[-1])
    except ValueError:
        return None


class DynamicExperimentError(RuntimeError):
    """A safe, user-actionable dynamic experiment configuration error."""


@dataclass(frozen=True)
class RunnerSpec:
    task_id: str
    family: str
    task_number: str
    data_dir: Path
    image: str
    command: tuple[str, ...]
    input_mount: str
    volumes: tuple[tuple[Path, str], ...]
    writable_out: bool = False


@dataclass
class DynamicExperimentResult:
    kind: str = "dynamic_experiment"
    experiment_id: str = ""
    task_id: str = ""
    mode: str = "vul"
    input_ref: str = ""
    input_sha256: str = ""
    input_size: int = 0
    raw_exit_code: int | None = None
    signal: str | None = None
    status: str = "runner_error"
    timed_out: bool = False
    elapsed_seconds: float = 0.0
    stdout_ref: str = ""
    stderr_ref: str = ""
    purpose: str = ""
    hypothesis_ref: str = ""
    runner_image: str = ""
    data_root: str = ""
    error: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class DataCoverageReport:
    total: int
    available: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)


@dataclass
class DynamicBudget:
    """Budget for one task's dynamic experiments within a single session."""

    max_experiments_per_task: int = DEFAULT_MAX_EXPERIMENTS_PER_TASK
    max_total_dynamic_seconds: float = DEFAULT_MAX_TOTAL_DYNAMIC_SECONDS
    dynamic_run_timeout: int = DEFAULT_RUN_TIMEOUT
    build_script_timeout: int = 60
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES


def _run_build_script(script: str, work_dir: Path, timeout: int) -> tuple[int | None, Path | None]:
    """Run a model-authored construction script in isolation; returns (rc, produced).

    The script runs with the Python std-lib interpreter only, in its own
    directory, and must create `input.bin` in the current directory. Nothing
    outside the work dir is reachable through the script's own code.
    """
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    script_path = work_dir / "build_input.py"
    script_path.write_text(script, encoding="utf-8")
    produced = work_dir / "input.bin"
    if produced.exists():
        produced.unlink()
    rc: int | None = None
    with (work_dir / "build.stdout.txt").open("w", encoding="utf-8") as fout, \
         (work_dir / "build.stderr.txt").open("w", encoding="utf-8") as ferr:
        try:
            proc = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(work_dir),
                stdout=fout,
                stderr=ferr,
                text=True,
                timeout=max(1, timeout),
            )
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            rc = None
    return rc, produced if produced.is_file() and produced.stat().st_size > 0 else None


def _read_summary(ref: str | Path, limit: int) -> tuple[str, bool]:
    """Read a bounded text summary from an archived run output file."""
    path = Path(ref)
    if not path.is_file():
        return "", False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", False
    truncated = len(text) > limit
    return text[:limit], truncated


class DynamicWorkbench:
    """Model-usable dynamic experiment workbench bound to one task session.

    The model calls `write_input` then `run_experiment`; the workbench owns the
    task binding, the research workspace, and the per-session budget. Results
    are observations only — never a vulnerability verdict.
    """

    def __init__(
        self,
        task_id: str,
        *,
        research_root: Path = RESEARCH_ROOT,
        budget: DynamicBudget | None = None,
        tasks_file: Path = DEFAULT_TASKS_FILE,
        data_root: Path = DEFAULT_DATA_ROOT,
        workspace_roots: tuple[Path, ...] = (PROJECT_ROOT, LOGS_DIR, RESEARCH_ROOT),
        runner: Callable | None = None,
        summary_bytes: int = DEFAULT_STDOUT_STDERR_SUMMARY_BYTES,
    ):
        self.task_id = task_id
        self.task_log_name = task_id.replace(":", "_")
        self.session_root = Path(research_root) / self.task_log_name
        self.inputs_dir = self.session_root / "inputs"
        self.experiments_dir = self.session_root / "experiments"
        self.budget = budget or DynamicBudget()
        self.tasks_file = Path(tasks_file)
        self.data_root = Path(data_root)
        self.workspace_roots = workspace_roots
        # `runner=None` means the real subprocess runner; callers (e.g. the
        # investigation loop with `dynamic_runner=None`) must not disable it.
        self.runner = runner if runner is not None else subprocess.run
        self.summary_bytes = summary_bytes
        self.experiments_run = 0
        self.total_seconds = 0.0
        self.exhausted = False
        self.clean_exits = 0

    # -- model tool: exp_write ------------------------------------------------
    def write_input(self, name: str, hex_text: str) -> dict[str, Any]:
        """Write a small candidate input from hex into the current task session.

        The name is validated against a safe token charset; the file always lands
        under `research/<current task>/inputs/`, never across tasks or outside.
        """
        name = str(name or "").strip()
        if not _INPUT_NAME_RE.fullmatch(name):
            raise DynamicExperimentError(
                f"input name must match [A-Za-z0-9_-]{{1,64}}, got {name!r} (no path separators, no '..')"
            )
        try:
            data = bytes.fromhex(str(hex_text or "").strip())
        except ValueError:
            raise DynamicExperimentError("exp_write hex argument is invalid (expected continuous hex digits)") from None
        if not data:
            raise DynamicExperimentError("exp_write produced an empty input")
        if len(data) > self.budget.max_input_bytes:
            raise DynamicExperimentError(
                f"exp_write input exceeds {self.budget.max_input_bytes} bytes: {len(data)}"
            )
        self.inputs_dir.mkdir(parents=True, exist_ok=True)
        path = (self.inputs_dir / f"{name}.bin").resolve()
        if self.session_root.resolve() not in path.parents:
            raise DynamicExperimentError("exp_write path escaped the current task session")
        path.write_bytes(data)
        return {
            "input_ref": str(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "path": str(path),
        }

    # -- model tool: exp_build (script construction) --------------------------
    def build_input(self, name: str, script: str) -> dict[str, Any]:
        """Run a std-lib Python construction script in isolation and archive the
        produced input under `research/<current task>/inputs/<name>.bin`.

        The script must create `input.bin` in its working directory. Consumes
        one dynamic-budget action and its runtime counts toward the total.
        """
        name = str(name or "").strip()
        if not _INPUT_NAME_RE.fullmatch(name):
            raise DynamicExperimentError(
                f"input name must match [A-Za-z0-9_-]{{1,64}}, got {name!r} (no path separators, no '..')"
            )
        script = str(script or "").strip()
        if not script:
            raise DynamicExperimentError("exp_build script is empty")
        if self.exhausted or self.experiments_run >= self.budget.max_experiments_per_task:
            raise DynamicExperimentError("dynamic experiment budget exhausted (max experiments per task reached)")
        work_dir = self.session_root / ".build" / name
        started = time.monotonic()
        rc, produced = _run_build_script(script, work_dir, timeout=self.budget.build_script_timeout)
        elapsed = round(time.monotonic() - started, 3)
        self.experiments_run += 1
        self.total_seconds += elapsed
        if self.total_seconds >= self.budget.max_total_dynamic_seconds:
            self.exhausted = True
        if rc is None:
            raise DynamicExperimentError("exp_build script timed out")
        if produced is None:
            stderr_tail = (work_dir / "build.stderr.txt").read_text(encoding="utf-8", errors="replace")[-1500:]
            raise DynamicExperimentError(f"exp_build script did not produce input.bin (rc={rc}): {stderr_tail[-800:]}")
        data = produced.read_bytes()
        if len(data) > self.budget.max_input_bytes:
            raise DynamicExperimentError(
                f"exp_build input exceeds {self.budget.max_input_bytes} bytes: {len(data)}"
            )
        self.inputs_dir.mkdir(parents=True, exist_ok=True)
        dest = (self.inputs_dir / f"{name}.bin").resolve()
        if self.session_root.resolve() not in dest.parents:
            raise DynamicExperimentError("exp_build path escaped the current task session")
        dest.write_bytes(data)
        return {
            "input_ref": str(dest),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "path": str(dest),
            "build_rc": rc,
            "elapsed_seconds": elapsed,
        }

    # -- model tool: exp_run --------------------------------------------------
    def _resolve_input_ref(self, input_ref: str | Path) -> str:
        """Normalize a model-supplied input reference to a usable file path.

        Models frequently pass the input_ref in a form that is not the exact
        exp_write/exp_build output: wrapped in quotes, a bare name, or a bare
        filename. Resolve those against the current task's inputs directory so
        the experiment actually runs instead of returning input_invalid.
        """
        ref = str(input_ref or "").strip()
        if len(ref) >= 2 and ref[0] in "\"'" and ref[-1] == ref[0]:
            ref = ref[1:-1].strip()
        path = Path(ref)
        if path.is_absolute():
            return ref
        project_candidate = PROJECT_ROOT / ref
        if project_candidate.is_file():
            return str(project_candidate)
        candidates = [ref]
        if not ref.endswith(".bin"):
            candidates.append(ref + ".bin")
        for name in candidates:
            candidate = self.inputs_dir / name
            if candidate.is_file():
                return str(candidate)
        return ref

    def _budget_snapshot(self) -> dict[str, Any]:
        return {
            "experiments_run": self.experiments_run,
            "max_experiments_per_task": self.budget.max_experiments_per_task,
            "total_seconds": round(self.total_seconds, 2),
            "max_total_dynamic_seconds": self.budget.max_total_dynamic_seconds,
        }

    def run_experiment(self, input_ref: str, purpose: str = "") -> dict[str, Any]:
        """Run one vulnerable-only experiment and return a structured observation.

        Only observations are returned; this never decides whether a vulnerability
        was demonstrated and never touches the fix runner or the submit path.
        """
        if self.exhausted or self.experiments_run >= self.budget.max_experiments_per_task:
            return {
                "kind": "dynamic_experiment_budget",
                "status": "budget_exhausted",
                "budget": self._budget_snapshot(),
                "error": "dynamic experiment budget exhausted (max experiments per task reached)",
            }
        input_ref = self._resolve_input_ref(input_ref)
        result = run_vulnerable_experiment(
            self.task_id,
            input_ref,
            purpose=str(purpose or ""),
            data_root=self.data_root,
            tasks_file=self.tasks_file,
            log_root=self.experiments_dir,
            workspace_roots=self.workspace_roots,
            run_timeout=self.budget.dynamic_run_timeout,
            max_input_bytes=self.budget.max_input_bytes,
            max_output_bytes=self.budget.max_output_bytes,
            runner=self.runner,
            task_subdir=False,
        )
        self.experiments_run += 1
        elapsed = float(result.get("elapsed_seconds") or 0.0)
        self.total_seconds += elapsed
        if self.total_seconds >= self.budget.max_total_dynamic_seconds:
            self.exhausted = True
        observation = self._observation(result, self._budget_snapshot())
        if observation.get("status") == "completed" and observation.get("raw_exit_code") == 0:
            self.clean_exits += 1
        return observation

    # -- model tool: exp_diff -------------------------------------------------
    def compare_experiments(self, input_a: str, input_b: str, purpose: str = "") -> dict[str, Any]:
        """Run two inputs on the vulnerable binary and return a comparison.

        Compare a candidate against a KNOWN-VALID baseline (a `TOOL: template`
        or seed input): matching behavior means the candidate was accepted and
        parsed (adjust the trigger); differing behavior (a rejected entry_hint,
        different execution time) means it was likely rejected at the entry
        (fix the structure). Costs two experiment budget units.
        """
        obs_a = self.run_experiment(input_a, f"{purpose} (a)") if purpose else self.run_experiment(input_a, "(a)")
        obs_b = self.run_experiment(input_b, f"{purpose} (b)") if purpose else self.run_experiment(input_b, "(b)")
        a_exec = _exec_ms(obs_a.get("stderr", ""))
        b_exec = _exec_ms(obs_b.get("stderr", ""))
        return {
            "kind": "dynamic_experiment_diff",
            "purpose": purpose,
            "input_a": obs_a.get("input_ref", ""),
            "input_b": obs_b.get("input_ref", ""),
            "a": self._diff_brief(obs_a),
            "b": self._diff_brief(obs_b),
            "same_rc": obs_a.get("raw_exit_code") == obs_b.get("raw_exit_code"),
            "same_signal": obs_a.get("signal") == obs_b.get("signal"),
            "same_sanitizer": bool(obs_a.get("sanitizer_report")) == bool(obs_b.get("sanitizer_report")),
            "same_entry_hint": bool(obs_a.get("entry_hint")) == bool(obs_b.get("entry_hint")),
            "a_exec_ms": a_exec,
            "b_exec_ms": b_exec,
            "exec_ms_diff": (a_exec - b_exec) if a_exec is not None and b_exec is not None else None,
            "budget": obs_b.get("budget"),
        }

    @staticmethod
    def _diff_brief(obs: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": obs.get("status"),
            "raw_exit_code": obs.get("raw_exit_code"),
            "signal": obs.get("signal"),
            "sanitizer_report": bool(obs.get("sanitizer_report")),
            "entry_hint": obs.get("entry_hint"),
            "input_size": obs.get("input_size"),
            "input_ref": obs.get("input_ref"),
            "stderr": str(obs.get("stderr") or "")[:1200],
        }

    def _observation(self, result: dict[str, Any], budget: dict[str, Any]) -> dict[str, Any]:
        stdout, stdout_truncated = _read_summary(result.get("stdout_ref", ""), self.summary_bytes)
        stderr, stderr_truncated = _read_summary(result.get("stderr_ref", ""), self.summary_bytes)
        sanitizer_report = any(
            marker in stderr for marker in
            ("AddressSanitizer", "MemorySanitizer", "UndefinedBehaviorSanitizer", "SUMMARY:")
        )
        observation = {
            "kind": "dynamic_experiment",
            "experiment_id": result.get("experiment_id", ""),
            "status": result.get("status", "runner_error"),
            "raw_exit_code": result.get("raw_exit_code"),
            "signal": result.get("signal"),
            "timed_out": bool(result.get("timed_out")),
            "elapsed_seconds": result.get("elapsed_seconds"),
            "input_ref": result.get("input_ref", ""),
            "input_sha256": result.get("input_sha256", ""),
            "input_size": result.get("input_size"),
            "purpose": result.get("purpose", ""),
            "sanitizer_report": sanitizer_report,
            "entry_hint": _entry_hint(stderr),
            "stdout": stdout,
            "stdout_truncated": stdout_truncated,
            "stderr": stderr,
            "stderr_truncated": stderr_truncated,
            "stdout_ref": result.get("stdout_ref", ""),
            "stderr_ref": result.get("stderr_ref", ""),
            "error": result.get("error", ""),
            "budget": budget,
        }
        if result.get("error"):
            observation["error"] = result["error"]
        return observation


def load_allowed_tasks(path: Path = DEFAULT_TASKS_FILE) -> set[str]:
    """Load the project task allowlist without contacting a server."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DynamicExperimentError(f"cannot load task allowlist: {path}: {exc}") from exc
    if not isinstance(data, list):
        raise DynamicExperimentError("task allowlist must be a JSON list")
    tasks = {str(item).strip() for item in data if str(item).strip()}
    invalid = sorted(task for task in tasks if task.count(":") != 1 or task.split(":", 1)[0] not in {"arvo", "oss-fuzz"})
    if invalid:
        raise DynamicExperimentError(f"unsupported task ids in allowlist: {invalid[:5]}")
    return tasks


def _safe_task_number(task_id: str) -> tuple[str, str]:
    family, number = task_id.split(":", 1) if ":" in task_id else ("", "")
    if family not in {"arvo", "oss-fuzz"} or not number.isdigit():
        raise DynamicExperimentError(f"unsupported task id: {task_id}")
    return family, number


def _required_data(task_id: str, data_root: Path, *, mode: str = "vul") -> tuple[Path, list[Path]]:
    family, number = _safe_task_number(task_id)
    base = data_root / family / number / mode
    if family == "arvo":
        required = [base / "arvo", base / "libs", base / "out"]
    else:
        required = [base / "metadata.json", base / "out"]
    return base, required


def _oss_fuzz_target(base: Path) -> str:
    metadata_path = base / "metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DynamicExperimentError(f"invalid OSS-Fuzz metadata: {metadata_path}: {exc}") from exc
    target = str(metadata.get("fuzz_target") or "").strip()
    if not target or Path(target).name != target:
        raise DynamicExperimentError(f"invalid fuzz_target in {metadata_path}")
    if not (base / "out" / target).is_file():
        raise DynamicExperimentError(f"fuzz target missing: {base / 'out' / target}")
    return target


def inspect_vulnerable_data(
    *,
    tasks_file: Path = DEFAULT_TASKS_FILE,
    data_root: Path = DEFAULT_DATA_ROOT,
) -> dict[str, Any]:
    """Inspect vulnerable-only binary data for the configured task list.

    This is a read-only inventory operation.  It does not inspect fix data,
    contact a registry, start Docker, or download missing assets.
    """
    tasks = sorted(load_allowed_tasks(Path(tasks_file)))
    report = DataCoverageReport(total=len(tasks))
    for task_id in tasks:
        try:
            family, _ = _safe_task_number(task_id)
            base, required = _required_data(task_id, Path(data_root))
            missing = [str(path) for path in required if not path.exists()]
            if missing:
                report.missing.append(f"{task_id}: missing {missing}")
                continue
            if family == "oss-fuzz":
                _oss_fuzz_target(base)
            report.available.append(task_id)
        except DynamicExperimentError as exc:
            report.malformed.append(f"{task_id}: {exc}")
    return asdict(report)


def resolve_runner_spec(task_id: str, *, data_root: Path = DEFAULT_DATA_ROOT, allowed_tasks: set[str] | None = None, mode: str = "vul") -> RunnerSpec:
    """Resolve one allowlisted task to its binary-only runner.

    `mode="vul"` runs the vulnerable build; `mode="fix"` runs the fixed build.
    Both are binary-only: the fixed build exposes only an exit code, never source
    or diff. This lets the model locally verify whether a PoC is fix-specific
    without touching fix source or the submit server.
    """
    if mode not in ("vul", "fix"):
        raise DynamicExperimentError(f"unsupported mode: {mode!r} (expected 'vul' or 'fix')")
    if allowed_tasks is not None and task_id not in allowed_tasks:
        raise DynamicExperimentError(f"task is not in the allowed experiment list: {task_id}")
    family, number = _safe_task_number(task_id)
    base, required = _required_data(task_id, data_root, mode=mode)
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise DynamicExperimentError(f"{mode} runner data missing for {task_id}: {missing}")

    if family == "arvo":
        volumes = (
            (base / "arvo", "/arvo"),
            (base / "libs", "/out-libs"),
            (base / "out", "/out"),
        )
        command = ("env", "LD_LIBRARY_PATH=/out-libs", "/bin/bash", "/arvo")
        input_mount = "/tmp/poc"
    else:
        target = _oss_fuzz_target(base)
        volumes = ((base / "out", "/out"),)
        command = ("reproduce", target)
        input_mount = "/testcase"
    return RunnerSpec(
        task_id=task_id,
        family=family,
        task_number=number,
        data_dir=base,
        image=DEFAULT_RUNNER_IMAGE,
        command=command,
        input_mount=input_mount,
        volumes=volumes,
        writable_out=family != "arvo",
    )


def _within(path: Path, roots: tuple[Path, ...]) -> bool:
    resolved = path.resolve()
    return any(resolved == root.resolve() or root.resolve() in resolved.parents for root in roots)


def resolve_input(input_ref: str | Path, *, workspace_roots: tuple[Path, ...] = (PROJECT_ROOT, LOGS_DIR), max_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> Path:
    path = Path(input_ref)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    path = path.resolve()
    if not _within(path, workspace_roots):
        raise DynamicExperimentError(f"input is outside the experiment workspace: {path}")
    if not path.is_file():
        raise DynamicExperimentError(f"input file missing: {path}")
    size = path.stat().st_size
    if size > max_bytes:
        raise DynamicExperimentError(f"input exceeds {max_bytes} bytes: {size}")
    return path


def _signal_name(code: int | None) -> str | None:
    if code is None or not 129 <= code <= 255:
        return None
    names = {9: "SIGKILL", 11: "SIGSEGV", 6: "SIGABRT", 4: "SIGILL", 8: "SIGFPE", 13: "SIGPIPE"}
    return names.get(code - 128, f"signal-{code - 128}")


def _bounded_text(value: bytes, limit: int) -> bytes:
    return value[:max(0, limit)]


def build_docker_command(spec: RunnerSpec, input_path: Path, *, run_timeout: int = DEFAULT_RUN_TIMEOUT, writable_out_dir: Path | None = None) -> list[str]:
    """Build a fixed Docker CLI command; caller cannot provide Docker options.

    `writable_out_dir` replaces the read-only `/out` mount with a writable copy
    (OSS-Fuzz wrappers create a working dir under `/out`); the original task
    data is never made writable.

    Hardening (M-05 audit): cap-drop ALL, no-new-privileges, pids/mem/cpu
    limits. `--user 65534` is deliberately NOT set: OSS-Fuzz wrappers write to
    the writable `/out` copy, which a nobody user cannot; adding it would break
    experiments. Revisit if a per-run workdir with 777 perms is provided.
    """
    command = ["docker", "run", "--rm", "--network", "none",
               "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               "--pids-limit", "256",
               "--memory", "2g",
               "--cpus", "2"]
    for host_path, container_path in spec.volumes:
        if writable_out_dir is not None and container_path == "/out":
            command.extend(["--volume", f"{Path(writable_out_dir).resolve()}:{container_path}"])
        else:
            command.extend(["--volume", f"{host_path.resolve()}:{container_path}:ro"])
    command.extend(["--volume", f"{input_path.resolve()}:{spec.input_mount}:ro"])
    command.extend([spec.image, "timeout", "-s", "SIGKILL", str(run_timeout), *spec.command])
    return command


def run_vulnerable_experiment(
    task_id: str,
    input_ref: str | Path,
    *,
    purpose: str = "",
    hypothesis_ref: str = "",
    mode: str = "vul",
    data_root: Path = DEFAULT_DATA_ROOT,
    tasks_file: Path = DEFAULT_TASKS_FILE,
    log_root: Path = LOGS_DIR / "dynamic_experiments",
    workspace_roots: tuple[Path, ...] = (PROJECT_ROOT, LOGS_DIR),
    run_timeout: int = DEFAULT_RUN_TIMEOUT,
    docker_timeout: int = DEFAULT_DOCKER_TIMEOUT,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    runner=subprocess.run,
    task_subdir: bool = True,
) -> dict[str, Any]:
    """Run one binary-only experiment and archive observations.

    The default runner is injectable for offline tests. No source, diff, or
    submit endpoint is reachable through this function.

    `mode="vul"` runs the vulnerable build (research/verification); `mode="fix"`
    runs the fixed build and returns its exit code — a local proxy for the
    submit-fix verdict, exposing no fix source or diff.

    `task_subdir=False` archives directly under `log_root/<experiment_id>/` for
    callers that already scope `log_root` by task session (e.g. DynamicWorkbench).
    """
    experiment_id = f"exp_{int(time.time() * 1000)}"
    archive_base = Path(log_root)
    if task_subdir:
        archive_base = archive_base / task_id.replace(":", "_")
    experiment_dir = archive_base / experiment_id
    result = DynamicExperimentResult(
        experiment_id=experiment_id,
        task_id=task_id,
        input_ref=str(input_ref),
        purpose=str(purpose),
        hypothesis_ref=str(hypothesis_ref),
        data_root=str(Path(data_root).resolve()),
    )
    try:
        allowed = load_allowed_tasks(Path(tasks_file))
        spec = resolve_runner_spec(task_id, data_root=Path(data_root), allowed_tasks=allowed, mode=mode)
        input_path = resolve_input(input_ref, workspace_roots=workspace_roots, max_bytes=max_input_bytes)
        data = input_path.read_bytes()
        result.input_sha256 = hashlib.sha256(data).hexdigest()
        result.input_size = len(data)
        result.runner_image = spec.image
        experiment_dir.mkdir(parents=True, exist_ok=True)
        archived_input = experiment_dir / "input.bin"
        archived_input.write_bytes(data)
        result.input_ref = str(archived_input)
        writable_out_dir: Path | None = None
        if getattr(spec, "writable_out", False):
            writable_out_dir = experiment_dir / "out_stage"
            shutil.copytree(spec.data_dir / "out", writable_out_dir, dirs_exist_ok=True)
        command = build_docker_command(spec, archived_input, run_timeout=run_timeout, writable_out_dir=writable_out_dir)
        started = time.monotonic()
        try:
            completed = runner(
                command,
                capture_output=True,
                timeout=max(1, docker_timeout),
                check=False,
            )
            result.raw_exit_code = completed.returncode
            result.signal = _signal_name(completed.returncode)
            result.timed_out = completed.returncode == 137
            result.status = "timed_out" if result.timed_out else ("crashed" if result.signal else "completed")
            stdout = _bounded_text(completed.stdout or b"", max_output_bytes)
            stderr = _bounded_text(completed.stderr or b"", max_output_bytes)
        except subprocess.TimeoutExpired as exc:
            result.status = "timed_out"
            result.timed_out = True
            result.error = "docker wait timeout"
            stdout = _bounded_text(exc.stdout or b"", max_output_bytes)
            stderr = _bounded_text(exc.stderr or b"", max_output_bytes)
        except OSError as exc:
            result.status = "runner_error"
            result.error = str(exc)[:1000]
            stdout, stderr = b"", b""
        result.elapsed_seconds = round(time.monotonic() - started, 3)
        (experiment_dir / "stdout.txt").write_bytes(stdout)
        (experiment_dir / "stderr.txt").write_bytes(stderr)
        result.stdout_ref = str(experiment_dir / "stdout.txt")
        result.stderr_ref = str(experiment_dir / "stderr.txt")
    except DynamicExperimentError as exc:
        result.status = "input_invalid" if "input" in str(exc).lower() else "task_data_missing"
        result.error = str(exc)[:2000]
        experiment_dir.mkdir(parents=True, exist_ok=True)
    result_path = experiment_dir / "result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return asdict(result)
