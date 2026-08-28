#!/usr/bin/env python3
"""Distill reflections into human-reviewable candidate knowledge entries.

Two commands:
  collect  - aggregate logs/reflections/ into a de-identified needs list
             (logs/distill_input/<batch>_needs.json)
  run      - start an opencode session where the model searches the web and
             drafts candidate knowledge entries from a needs list
             (logs/distill_pending/<batch>_draft.json)

The model NEVER writes directly into knowledge/. It only produces candidates
that a human reviews and then imports with import_knowledge.py.

NOTE: the `run` command requires network access (models must search the web).
Run `sudo bash ~/netunlock.sh` first, then `sudo bash ~/netlock.sh` after.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
REFLECT_ROOT = PROJECT_ROOT / "logs" / "reflections"
DISTILL_INPUT = PROJECT_ROOT / "logs" / "distill_input"
DISTILL_PENDING = PROJECT_ROOT / "logs" / "distill_pending"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _load_index() -> list[dict]:
    records: list[dict] = []
    index = REFLECT_ROOT / "index.jsonl"
    if index.is_file():
        for line in index.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def cmd_collect(args: argparse.Namespace) -> None:
    """Aggregate reflections into a de-identified needs list."""
    records = _load_index()
    if not records:
        print("no reflections found in logs/reflections/", file=sys.stderr)
        raise SystemExit(2)
    # De-identify: drop task_id; keep the knowledge-relevant fields. The
    # task_outcome (success/fail, backfilled by batch_solve) is kept for source
    # marking — needs from FAILED tasks may encode wrong hypotheses and are
    # treated as provisional downstream.
    needs = []
    for r in records:
        outcome = str(r.get("task_outcome") or "").strip()
        needs.append({
            "domain": r.get("domain", "other"),
            "knowledge_gap": r.get("knowledge_gap", ""),
            "narrative": r.get("narrative", ""),
            "evidence": r.get("evidence", ""),
            "suggested_learning": r.get("suggested_learning", ""),
            "source_outcome": outcome if outcome in ("success", "fail") else "unknown",
        })
    batch = args.batch or _now_stamp()
    DISTILL_INPUT.mkdir(parents=True, exist_ok=True)
    out = DISTILL_INPUT / f"{batch}_needs.json"
    payload = {
        "kind": "distill_needs",
        "batch": batch,
        "created_at": _utcnow(),
        "count": len(needs),
        "needs": needs,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "ok": True,
        "needs_file": str(out),
        "count": len(needs),
        "domains": sorted({n["domain"] for n in needs}),
    }, ensure_ascii=False, indent=2))


def cmd_run(args: argparse.Namespace) -> None:
    """Start an opencode session to draft candidate entries from a needs list."""
    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"needs file not found: {input_path}", file=sys.stderr)
        raise SystemExit(2)
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    needs = payload.get("needs", [])
    if not needs:
        print("needs list is empty", file=sys.stderr)
        raise SystemExit(2)

    needs_json = json.dumps(needs, ensure_ascii=False, indent=2)
    batch = payload.get("batch") or input_path.stem
    DISTILL_PENDING.mkdir(parents=True, exist_ok=True)
    out = DISTILL_PENDING / f"{batch}_draft.json"

    prompt = f"""You are the knowledge-distillation assistant for a vulnerability-research knowledge library.

Below is a de-identified list of knowledge GAPS that models hit while solving tasks. For each gap,
your job is to research and draft a GENERAL, reusable knowledge entry that would help a future agent.

INPUT (de-identified needs list):
{needs_json}

TASK:
For EACH need, attempt to produce one candidate knowledge entry that captures the underlying knowledge.
Use web search / web fetch to verify or enrich the technical details (e.g. exact semantics of a
library helper, a format's framing rules, a sanitizer behavior). You have network access — but if
web fetch fails or returns nothing, fall back to your own technical knowledge and still produce the
best entry you can (with sources=["internal"] if no URL was usable). Do not stall on searching.

For each need, decide ONE of:
1. A full entry:  {{"need_index": <i>, "title": "...", "summary": "...", "content": "...", "sources": ["url..."]}}
2. Skip:          {{"need_index": <i>, "skip": true, "skip_reason": "..."}}   (use only if you genuinely
                  could not gather enough information; better to attempt an entry)

RULES:
- Entries must be GENERAL and REUSABLE: describe the underlying technical knowledge — an objective
  fact, a mechanism, a format structure, library/API semantics, a sanitizer behavior, or a strategy
  that helps solving such tasks — never one task's answer. Objective/cognitive knowledge is fully
  welcome as-is (e.g. 'FuzzedDataProvider consumes integral values from the END of the buffer', 'an
  ET_DYN needs PT_LOAD + PT_DYNAMIC with DT_HASH/DT_SYMTAB/DT_STRTAB'); you do NOT need to recast it as
  a how-to-do-it "experience/lesson".
- SANITIZE: no task id, no project-specific bug description, no PoC bytes, no exact trigger values,
  no file line numbers that identify a task, no construction scripts. In particular: NEVER include any
  fix-side handling detail, fix patch content, or a vulnerability-vs-fix diff comparison. The fix side
  is out of scope; entries must stay fix-agnostic.
- SOURCE MARKING: each need carries source_outcome (success|fail). Needs from FAILED tasks are
  PROVISIONAL — the model that hit the gap may have held wrong hypotheses. When drafting from a
  failed-source need, verify the mechanism against web/source before asserting it, and prefer stating
  the objective knowledge (format structure / mechanism / sanitizer / tool behavior) over the task's
  specific — possibly mistaken — root-cause claim. Never mark a guess as an established fact.
- It IS allowed to name formats/libraries/APIs generally (e.g. 'libgit2 git__prefixcmp', 'MNG chunk
  framing', 'libFuzzer -runs=0'), because those are reusable domain knowledge.
- content should be 2-6 sentences, precise, with correct technical terms.
- Include URLs you used under sources.

Output ONLY a JSON object:
{{"entries": [ ...each entry or skip record... ]}}
Do not include the input list in your output.

After producing the JSON, reply with the single word DONE."""

    # Pass the (possibly large) prompt via stdin instead of argv: opencode run
    # treats stdin as the message when no positional message is given. This
    # avoids `Argument list too long` for batches with many/large narratives.
    cmd = [
        "timeout", "-k", "30", str(args.timeout),
        "opencode", "run", "--format", "json",
        "--title", f"distill-{batch}",
    ]
    print(f"=== Starting distill session (batch={batch}, needs={len(needs)}, timeout={args.timeout}s) ===")
    stdout = ""
    stderr = ""
    exit_code = 124
    try:
        result = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=args.timeout + 60,
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        exit_code = result.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr or "").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        print(f"distill session timed out; saving whatever was produced", file=sys.stderr)
    print(f"opencode exit={exit_code}")

    # Extract the model's final JSON object (from the last step text).
    entries = _extract_entries(stdout)

    # Backfill source_outcome onto each entry from the needs list (keyed by
    # need_index) so human approval can weigh entries that came from failed
    # tasks (provisional, may encode wrong hypotheses).
    outcome_by_index: dict = {}
    for i, n in enumerate(needs):
        outcome_by_index[i] = str(n.get("source_outcome") or "unknown")
    for e in entries:
        if not isinstance(e, dict):
            continue
        idx = e.get("need_index")
        if isinstance(idx, int):
            e["source_outcome"] = outcome_by_index.get(idx, "unknown")
        elif isinstance(idx, str) and idx.isdigit():
            e["source_outcome"] = outcome_by_index.get(int(idx), "unknown")
        else:
            e.setdefault("source_outcome", "unknown")

    draft = {
        "kind": "distill_draft",
        "batch": batch,
        "created_at": _utcnow(),
        "source_needs": str(input_path),
        "needs_count": len(needs),
        "entries_count": len(entries),
        "entries": entries,
    }
    out.write_text(json.dumps(draft, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Keep the raw session for audit.
    (DISTILL_PENDING / f"{batch}_draft.session.jsonl").write_text(stdout, encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "draft_file": str(out),
        "entries_count": len(entries),
        "exit_code": exit_code,
        "note": "Candidates saved for HUMAN review. Import with import_knowledge.py after review.",
    }, ensure_ascii=False, indent=2))


def _extract_entries(stdout: str) -> list[dict]:
    """Pull the JSON entries array out of the opencode run output.

    The output is a JSONL event stream; the model's final message is a `text`
    event whose `part.text` holds the JSON. We first join all text parts, then
    find the last complete `{...entries...}` object (tolerating ```json fences).
    """
    import re
    # 1) If it looks like a JSONL event stream, extract the model text parts.
    joined = stdout
    if '"type":"text"' in stdout or '"type": "text"' in stdout:
        parts = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "text":
                t = (ev.get("part", {}) or {}).get("text", "")
                if t:
                    parts.append(t)
        if parts:
            joined = "\n".join(parts)
    # 2) strip fences
    text = re.sub(r"```(?:json)?\s*", "", joined)
    # 3) scan for { ... } objects containing an "entries" key
    candidates = []
    start = 0
    for _ in range(200):
        i = text.find("{", start)
        if i == -1:
            break
        depth = 0
        j = i
        in_str = False
        esc = False
        while j < len(text):
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        chunk = text[i:j + 1]
                        try:
                            obj = json.loads(chunk)
                            if isinstance(obj, dict) and "entries" in obj:
                                candidates.append(obj)
                        except json.JSONDecodeError:
                            pass
                        start = j + 1
                        break
            j += 1
        else:
            break
    if candidates:
        entries = candidates[-1].get("entries", [])
        if isinstance(entries, list):
            return entries
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Distill reflections into candidate knowledge entries")
    sub = parser.add_subparsers(dest="command", required=True)

    p_c = sub.add_parser("collect", help="aggregate reflections into a de-identified needs list")
    p_c.add_argument("--batch", default="", help="batch label (default: timestamp)")
    p_c.set_defaults(func=cmd_collect)

    p_r = sub.add_parser("run", help="start opencode session to draft candidate entries (needs network)")
    p_r.add_argument("--input", required=True, help="needs file from collect (logs/distill_input/*_needs.json)")
    p_r.add_argument("--timeout", type=int, default=1200, help="session timeout seconds (default 1200)")
    p_r.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
