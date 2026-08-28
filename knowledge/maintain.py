"""Offline maintenance of the experience knowledge base.

Extracts sanitized, reviewed experience entries from SUCCESSFUL task logs using
the LLM, then validates and appends them to knowledge/<domain>/entries.jsonl.

This runs OUTSIDE the agent loop (never a model tool). Inputs are only the
research notes and run summary of tasks that reached a verified success; the
LLM rewrites them into reusable natural-language lessons that:

- never contain task ids, project names, PoC bytes/hex, construction scripts,
  exact trigger parameters, fix/patch/repo-fix, VCS or Level-3 internals;
- describe reusable structure/construction/runtime reasoning instead of a
  specific answer.

Usage:
  python3 -m knowledge.maintain --task arvo:10400 [--task ...]
      --domain reasoning|format        (default: infer both, write each)
      --dry-run                        (validate+print, do not write)
      --max-entries N                  (cap entries per task)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import KNOWLEDGE_HOME, KNOWLEDGE_DOMAINS, KNOWLEDGE_ENTRY_FIELDS, KNOWLEDGE_STATUSES  # noqa: E402
from core.llm import chat  # noqa: E402

_SUPPORTED_TASKS = ("reasoning", "format")

EXTRACT_PROMPT = """You distill reusable research experience from a successful vulnerability investigation. Output ONLY a JSON array of experience entries.

Inputs: the model's research notes (round-indexed) and the run summary of a task that achieved a verified success (vulnerable-side crash + fixed-side clean).

For each reusable lesson you identify, emit one entry:
{{"id": "reasoning-NNN", "title": "<short title>", "summary": "<one-line what/why>", "content": "<natural-language lesson, 2-6 sentences>", "status": "candidate"}}

Rules (MUST follow):
- Domain is "reasoning": entry-judgment / legal-baseline / failure-explanation / mechanism-review / experiment-design lessons.
- Make it REUSABLE: describe the general research pattern, not one task's answer.
- SANITIZE strictly: no task id, no project/repo name, no CVE, no PoC bytes or hex, no exact file line numbers that identify the task, no construction script, no exact trigger values, no fix/patch/repo-fix/VCS/Level-3 details.
- A lesson must NOT be a blueprint that lets someone construct the successful input for this specific task without reading it.
- Only include lessons you are confident generalize. 0 entries is acceptable.
- id numbering within domain should start at 001; the writer will renumber to avoid collisions.
"""

FORMAT_PROMPT = """You distill reusable FORMAT-CONSTRUCTION experience from a successful vulnerability investigation. Output ONLY a JSON array of experience entries.

Inputs: the model's research notes (round-indexed) and the run summary of a task that achieved a verified success (vulnerable-side crash + fixed-side clean).

For each reusable lesson you identify, emit one entry:
{{"id": "format-NNN", "title": "<short title>", "summary": "<one-line what/why>", "content": "<natural-language lesson, 2-6 sentences>", "status": "candidate"}}

Rules (MUST follow):
- Domain is "format": the lessons must be FORMAT-SPECIFIC and concrete. KEEP the format family name (e.g. MNG/PNG/IVF/ELF/WASM/PDF/TIFF), the container structure, field layout, dependency/checksum relations, and the specific construction traps you discovered. DO NOT over-generalize to "structure matters" — that is useless.
- Examples of good format entries: "MNG/PNG chunk: 4-byte length, 4-byte type, data, CRC — the length check must cover the field read from chunk+1, not just chunk"; "IVF: 32-byte header then raw AV1 OBU; a truncated last frame parses but decode reads past it".
- SANITIZE: no task id, no project/repo name, no CVE, no COMPLETE PoC, no full input hex dump, no construction script, no fix/patch/repo-fix/VCS/Level-3 details. Format magic/header bytes (short signatures) and structural field offsets ARE allowed and encouraged.
- A lesson must NOT be a blueprint that lets someone construct the successful input for this specific task without reading it.
- Only include lessons you are confident about. 0 entries is acceptable.
- id numbering within domain should start at 001; the writer will renumber to avoid collisions.
"""


def _task_log_name(task_id: str) -> str:
    # research/<task>/ uses task_id.replace(":", "_") (e.g. oss-fuzz_383187490)
    return str(task_id or "").replace(":", "_")


def _logs_task_name(task_id: str) -> str:
    # logs/batch_*/tasks/<task>/ uses batch.py's convention (oss_fuzz_383187490)
    return str(task_id or "").replace("-fuzz:", "_fuzz_").replace(":", "_")


def _load_notes(task_id: str, research_root: Path) -> list[dict]:
    path = research_root / _task_log_name(task_id) / "notes.jsonl"
    notes: list[dict] = []
    if not path.is_file():
        return notes
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                notes.append(rec)
    return notes


# Batch log dirs to search for a task's run summary, in priority order. The
# first record with a verified success wins (its notes are the richest source).
DEFAULT_LOG_ROOTS = [
    "logs/batch_deepseek_full",
    "logs/batch_50_compact_v8",
    "logs/batch_sample_v10_compact6",
    "logs/batch_sample_v8_compact6",
    "logs/batch_sample_v7_compact6",
    "logs/batch_sample_v6_compact6",
    "logs/batch_sample_v5_compact6",
    "logs/batch_sample_v4_compact6",
    "logs/batch_sample_v3_compact6",
    "logs/batch_sample_v2_compact",
    "logs/batch_sample_v1",
]


def _load_run_summary(task_id: str, log_roots: list[Path]) -> dict:
    """Find the task's run summary across log roots, preferring a success record."""
    best: dict | None = None
    for log_root in log_roots:
        candidates = [
            log_root / "tasks" / _logs_task_name(task_id) / "run_summary.json",
            log_root / "tasks" / _logs_task_name(task_id) / "process_finished.json",
        ]
        for path in candidates:
            if path.is_file():
                try:
                    d = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if _is_success(d):
                    return d
                if best is None:
                    best = d
    return best or {}


def _success_tasks_from_summary(summary_path: Path) -> list[str]:
    """Return task ids marked success in a batch summary.json."""
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read summary {summary_path}: {exc}") from exc
    tasks = data.get("tasks") if isinstance(data, dict) else data
    out: list[str] = []
    for result in tasks if isinstance(tasks, list) else []:
        if not isinstance(result, dict):
            continue
        status = str(result.get("final_status") or result.get("status") or "")
        if status == "success" or bool(result.get("fix_verified_success")):
            tid = str(result.get("task_id") or "").strip()
            if tid:
                out.append(tid)
    return sorted(set(out))


def _is_success(run_summary: dict) -> bool:
    final = str(run_summary.get("final_status") or run_summary.get("status") or "")
    return final == "success" or bool(run_summary.get("fix_verified_success"))


def _build_input(task_id: str, notes: list[dict], run_summary: dict) -> str:
    parts = [f"## Task run summary\n{json.dumps({k: run_summary.get(k) for k in ('final_status', 'handoff_status', 'tool_calls', 'rounds')}, ensure_ascii=False)}"]
    if notes:
        note_lines = [f"- round {n.get('round')}: {str(n.get('content') or '')[:2000]}" for n in notes]
        parts.append("## Research notes (model-authored)\n" + "\n".join(note_lines))
    return "\n\n".join(parts)


def _parse_entries(text: str, domain: str) -> list[dict]:
    import re
    text = str(text or "").strip()
    if not text:
        return []
    data = None
    # 1) try the whole text as JSON
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            data = parsed
    except json.JSONDecodeError:
        pass
    # 2) try first complete array from a wrapping block (```json ... ``` or prose)
    if data is None:
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group(0))
                if isinstance(parsed, list):
                    data = parsed
            except json.JSONDecodeError:
                pass
    # 3) tolerate truncation: decode array items one by one with raw_decode
    if data is None:
        decoder = json.JSONDecoder()
        start = text.find("[")
        if start >= 0:
            idx = start + 1
            collected = []
            try:
                while True:
                    while idx < len(text) and text[idx] in " \n\t,":
                        idx += 1
                    if idx >= len(text) or text[idx] == "]":
                        break
                    item, end = decoder.raw_decode(text, idx)
                    idx = end
                    if isinstance(item, dict):
                        collected.append(item)
            except (json.JSONDecodeError, ValueError):
                pass
            if collected:
                data = collected
    if data is None:
        return []
    entries = []
    for item in data:
        if not isinstance(item, dict):
            continue
        entry = {
            "id": str(item.get("id") or f"{domain}-000"),
            "title": str(item.get("title") or "").strip(),
            "summary": str(item.get("summary") or "").strip(),
            "content": str(item.get("content") or "").strip(),
            "status": str(item.get("status") or "candidate").strip(),
        }
        if entry["title"] and entry["content"] and entry["status"] in KNOWLEDGE_STATUSES:
            entries.append(entry)
    return entries


def _next_id(domain: str, existing: list[dict]) -> str:
    max_num = 0
    for e in existing:
        eid = str(e.get("id") or "")
        if eid.startswith(f"{domain}-"):
            try:
                max_num = max(max_num, int(eid.rsplit("-", 1)[1]))
            except ValueError:
                continue
    return f"{domain}-{max_num + 1:03d}"


def _sanitize(entry: dict, domain: str) -> bool:
    """Sanitation guard per domain.

    reasoning: reject any long hex (task-specific bytes) — keep it generalized.
    format: reject COMPLETE PoC-scale hex and scripts, but ALLOW short format
    magic/header signatures (<=16 hex chars), which are the useful identifiers
    of a format family. Both reject obvious construction-script markers.
    """
    import re
    joined = " ".join(str(entry.get(k) or "") for k in ("title", "summary", "content"))
    if domain == "format":
        # reject very long hex (PoC-scale byte dumps), allow short magic
        if re.search(r"\b[a-f0-9]{32,}\b", joined, re.I):
            return False
    else:
        # reasoning: reject any 8+ hex string
        if re.search(r"\b[a-f0-9]{8,}\b", joined, re.I):
            return False
    # reject construction-script markers regardless of domain
    if re.search(r"(python3|#!/|subprocess|import\s+os|open\(|\.write\()", joined, re.I):
        return False
    return True


DEDUPE_PROMPT = """You are the librarian of an experience knowledge base. Given NEW experience entries mined from a task, and the library's EXISTING entries, decide which new entries are actually worth adding.

Rules:
- DROP a new entry if its semantic lesson is already covered by an existing entry (same lesson, even if phrased differently).
- MERGE: if a new entry adds a useful detail to an existing one, keep the new entry but only if it carries a distinct, non-redundant point; otherwise drop it.
- NEVER edit or rewrite existing entries. Only decide for the NEW entries: keep or drop.
- Output ONLY a JSON array of the NEW entries you choose to keep (each exactly as provided, with its id).

Existing entries:
{existing}

New entries:
{new}
"""


def _extract_kept_ids(text: str) -> set[str]:
    """Extract kept entry ids from the dedupe LLM's JSON array.

    The LLM is told to output only the new entries it keeps, but it may emit
    full objects ({"id": ...}), id-only objects ({"id": "x-1"}), or bare id
    strings (["x-1"]). Accept all three.
    """
    import re
    ids: set[str] = set()
    text = str(text or "").strip()
    if not text:
        return ids
    # bare strings in an array
    for m in re.finditer(r'"([A-Za-z0-9_\-]+)"', text):
        ids.add(m.group(1))
    # id fields of objects
    for m in re.finditer(r'"id"\s*:\s*"([A-Za-z0-9_\-]+)"', text):
        ids.add(m.group(1))
    return ids


def _dedupe_with_library(new_entries: list[dict], existing: list[dict], domain: str) -> list[dict]:
    """Use the LLM to drop new entries whose lesson is already in the library."""
    if not new_entries or not existing:
        return new_entries
    existing_text = json.dumps([{k: e.get(k) for k in ("id", "title", "summary", "content")} for e in existing], ensure_ascii=False)
    new_text = json.dumps([{k: e.get(k) for k in ("id", "title", "summary", "content")} for e in new_entries], ensure_ascii=False)
    prompt = DEDUPE_PROMPT.format(existing=existing_text[:20000], new=new_text[:20000])
    text = ""
    for _attempt in range(2):
        try:
            text, _usage = chat(
                [{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=4000,
                role="knowledge_maintain",
            )
        except Exception:
            text = ""
        if str(text or "").strip():
            break
    kept_ids = _extract_kept_ids(text)
    # if the LLM failed to return any parseable ids, keep everything (fail-safe,
    # never drop all entries on a parsing miss)
    if not kept_ids:
        return new_entries
    kept = [e for e in new_entries if str(e.get("id")) in kept_ids]
    return kept


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract sanitized experience entries from successful tasks")
    parser.add_argument("--task", action="append", default=None, help="task id, repeatable")
    parser.add_argument("--from-summary", type=Path, default=None, help="batch summary.json: process all success tasks in it")
    parser.add_argument("--domain", choices=_SUPPORTED_TASKS, default=None, help="domain to write (default: both)")
    parser.add_argument("--dry-run", action="store_true", help="validate and print, do not write")
    parser.add_argument("--write-lib", action="store_true",
                        help="显式开启直接写库（默认停用：只输出候选，人工审批入库请走 import_knowledge.py）")
    parser.add_argument("--max-entries", type=int, default=6)
    parser.add_argument("--research-root", type=Path, default=PROJECT_ROOT / "research")
    parser.add_argument("--log-root", action="append", default=None, help="batch log dir to search for run summaries (repeatable; default: all known batches)")
    args = parser.parse_args(argv)

    if args.task and args.from_summary:
        parser.error("use either --task or --from-summary, not both")
    if not args.task and not args.from_summary:
        parser.error("provide --task or --from-summary")
    task_ids = list(args.task or []) if args.task else _success_tasks_from_summary(args.from_summary)

    domains = [args.domain] if args.domain else _SUPPORTED_TASKS
    home = Path(KNOWLEDGE_HOME)
    log_roots = [Path(r) for r in (args.log_root or DEFAULT_LOG_ROOTS)]

    if args.from_summary:
        print(f"summary success tasks ({len(task_ids)}): {', '.join(task_ids)}")

    for task_id in task_ids:
        notes = _load_notes(task_id, args.research_root)
        run_summary = _load_run_summary(task_id, log_roots)
        if not _is_success(run_summary):
            print(f"skip {task_id}: not a verified success", file=sys.stderr)
            continue
        material = _build_input(task_id, notes, run_summary)
        print(f"== {task_id}: notes={len(notes)} material_chars={len(material)}")
        if not notes and not run_summary:
            print(f"   no notes/summary found", file=sys.stderr)
            continue

        for domain in domains:
            existing = []
            path = home / domain / "entries.jsonl"
            if path.is_file():
                with path.open("r", encoding="utf-8") as stream:
                    for line in stream:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            existing.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            prompt = FORMAT_PROMPT if domain == "format" else EXTRACT_PROMPT
            text = ""
            for attempt in range(3):
                try:
                    text, _usage = chat(
                        [{"role": "user", "content": prompt + "\n\n" + material}],
                        temperature=0.2,
                        max_tokens=8000,
                        role="knowledge_maintain",
                    )
                except Exception as exc:
                    print(f"   {domain}: LLM attempt {attempt + 1} failed: {exc}", file=sys.stderr)
                    text = ""
                if str(text or "").strip():
                    break
                if attempt < 2:
                    print(f"   {domain}: empty output, retrying ({attempt + 1}/2)", file=sys.stderr)
            entries = _parse_entries(text, domain)[: args.max_entries]
            accepted = []
            for e in entries:
                if _sanitize(e, domain):
                    accepted.append(e)
            if not accepted:
                print(f"   {domain}: 0 entries (extracted {len(entries)}, sanitized {len(entries) - len(accepted)})")
                print(f"   {domain}: raw model output head: {str(text)[:400]!r}")
                continue
            # 自动写库默认停用（M-04 审计）：仅 --write-lib 显式开启才写库。
            # 常规入库必须走人工审批流程：distill.py 产候选 → import_knowledge.py。
            if args.write_lib:
                before = len(accepted)
                accepted = _dedupe_with_library(accepted, existing, domain)
                dropped = before - len(accepted)
                if dropped:
                    print(f"   {domain}: library dedupe dropped {dropped} redundant entries")
            for i, e in enumerate(accepted):
                e["id"] = _next_id(domain, existing + accepted[:i])
            print(f"   {domain}: {len(accepted)} entries")
            for e in accepted:
                print(f"     {e['id']}: {e['title']} [{e['status']}]")
            if not args.write_lib:
                print(f"   (自动写库已停用；候选请经 distill + import_knowledge.py 人工审批入库，"
                      f"确需直接写库再加 --write-lib)")
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as stream:
                for e in accepted:
                    stream.write(json.dumps(e, ensure_ascii=False) + "\n")
            existing.extend(accepted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
