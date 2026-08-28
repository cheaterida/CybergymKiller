"""Task loader: resolve a CyberGym task id to its on-disk task directory."""
from __future__ import annotations

from pathlib import Path

from config import TASKS_DIR


class Task:
    def __init__(self, task_id: str, task_dir: Path):
        self.task_id = task_id
        self.task_dir = Path(task_dir)

    def __repr__(self) -> str:
        return f"Task(task_id={self.task_id!r}, task_dir={self.task_dir!s})"


def load_task(task_id: str) -> Task:
    # Some task directories use an all-underscore name (e.g. oss_fuzz_42535152)
    # while others preserve the hyphen (e.g. oss-fuzz_42535152). Try both.
    candidates = [task_id.replace(":", "_")]
    if "-" in candidates[0]:
        candidates.append(candidates[0].replace("-", "_"))
    for safe in candidates:
        task_dir = TASKS_DIR / safe
        if task_dir.is_dir():
            return Task(task_id, task_dir)
    raise FileNotFoundError(
        f"task directory not found for {task_id}: {TASKS_DIR / candidates[0]}"
    )
