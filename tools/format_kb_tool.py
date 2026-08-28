"""Wrapper exposing the external format-knowledge-base (format_kb) to the model.

format_kb is a separate project (121 formats, verified byte templates, field
offsets, dependency graphs and parser-risk fields). It is called as a read-only
subprocess so the main agent can (a) identify a format from header bytes,
(b) read a construction blueprint, and (c) obtain a verified valid template as
a mutation base. The knowledge base is never modified and nothing is injected
into the workflow — the model chooses when to call these tools.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from config import FORMAT_KB_HOME

_FORMAT_KB_SRC = Path(FORMAT_KB_HOME) / "src"
_FORMAT_KB_TIMEOUT = 60


def format_kb_available() -> bool:
    return (_FORMAT_KB_SRC / "format_kb" / "__init__.py").is_file()


def _run_kb(args: list[str], *, timeout: int = _FORMAT_KB_TIMEOUT) -> str:
    """Run the format_kb CLI and return stdout (or an ERROR: line)."""
    env = dict(os.environ)
    pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(_FORMAT_KB_SRC) + (os.pathsep + pythonpath if pythonpath else "")
    proc = subprocess.run(
        [sys.executable, "-m", "format_kb.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode == 0:
        return out
    # nonzero return code with a valid JSON result (e.g. `match` with no hits)
    # is a legitimate outcome, not a failure.
    if out and out.lstrip().startswith(("[", "{")):
        return out
    return f"ERROR: format_kb {args[0] if args else ''} failed: {(err or out)[:1500]}"


def format_blueprint(format_id: str) -> str:
    """Return the machine-readable blueprint JSON for a format."""
    return _run_kb(["blueprint", str(format_id), "--json"])


def identify(hex_text: str) -> str:
    """Rank candidate formats from header bytes (hex)."""
    return _run_kb(["match", "--hex", str(hex_text)])


def template_bytes(format_id: str, *, allow_incomplete: bool = True) -> bytes:
    """Export the verified (or skeleton) template as raw bytes."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as stream:
        tmp = Path(stream.name)
    try:
        args = ["template", str(format_id), "--encoding", "raw", "--output", str(tmp), "--force"]
        if allow_incomplete:
            args.append("--allow-incomplete")
        output = _run_kb(args)
        if output.startswith("ERROR:"):
            return output.encode("utf-8")
        return tmp.read_bytes()
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
