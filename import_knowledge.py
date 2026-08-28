#!/usr/bin/env python3
"""Manually import distilled candidate entries into the knowledge library.

Reads a distill draft file (logs/distill_pending/*_draft.json), lets the user
approve entries by id (or approve-all), validates/sanitizes, assigns the next
free id, deduplicates against the existing library, and appends to
knowledge/<domain>/entries.jsonl.

Human-in-the-loop by design: nothing is imported until you explicitly approve.

Usage:
  python3 import_knowledge.py --input logs/distill_pending/2026-08-24_draft.json \
      --domain reasoning --approve 0,1,3
  python3 import_knowledge.py --input <file> --domain format --approve-all
  python3 import_knowledge.py --input <file> --domain reasoning --list     # show candidates only
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from knowledge.maintain import _sanitize, _next_id  # noqa: E402
from config import KNOWLEDGE_HOME, KNOWLEDGE_DOMAINS  # noqa: E402

DRAFT_ROOT = PROJECT_ROOT / "logs" / "distill_pending"


def _load_draft(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "entries" not in data:
        raise SystemExit(f"invalid draft file (missing 'entries'): {path}")
    return data


def _existing_entries(domain: str) -> list[dict]:
    path = KNOWLEDGE_HOME / domain / "entries.jsonl"
    existing: list[dict] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                existing.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return existing


def _dedupe_by_title(new_entry: dict, existing: list[dict]) -> bool:
    """Skip a new entry whose title closely matches an existing one."""
    new_title = str(new_entry.get("title") or "").strip().lower()
    if not new_title:
        return False
    for e in existing:
        if str(e.get("title") or "").strip().lower() == new_title:
            return True
    return False


def cmd_list(args: argparse.Namespace) -> None:
    draft = _load_draft(Path(args.input))
    entries = draft.get("entries", [])
    # Surface the distill source marking so approval can weigh provisional
    # entries that came from failed tasks.
    for e in entries:
        if isinstance(e, dict) and str(e.get("source_outcome") or "").strip() == "fail":
            e.setdefault("_source_note", "⚠ FAILED-source entry — hypothesis may be wrong; verify before approving")
    print(json.dumps(entries, ensure_ascii=False, indent=2))


def cmd_import(args: argparse.Namespace) -> None:
    domain = args.domain
    if domain not in KNOWLEDGE_DOMAINS:
        raise SystemExit(f"unknown domain {domain!r}; choose from {KNOWLEDGE_DOMAINS}")
    draft = _load_draft(Path(args.input))
    candidates = draft.get("entries", [])
    if not candidates:
        print("no candidate entries in draft", file=sys.stderr)
        return

    if args.approve_all:
        approved_idx = list(range(len(candidates)))
    elif args.approve:
        approved_idx = []
        want_all = False
        for token in args.approve.split(","):
            token = token.strip().lower()
            if not token:
                continue
            if token in ("all", "*"):
                want_all = True
                break
            try:
                approved_idx.append(int(token))
            except ValueError:
                print(f"invalid approval index: {token!r}", file=sys.stderr)
        if want_all:
            approved_idx = list(range(len(candidates)))
    else:
        print("provide --approve <idx,...> or --approve-all", file=sys.stderr)
        raise SystemExit(2)

    existing = _existing_entries(domain)
    path = KNOWLEDGE_HOME / domain / "entries.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)

    imported: list[dict] = []
    skipped: list[dict] = []
    for idx in approved_idx:
        if idx < 0 or idx >= len(candidates):
            skipped.append({"index": idx, "reason": "out of range"})
            continue
        cand = candidates[idx]
        if cand.get("skip"):
            skipped.append({"index": idx, "reason": cand.get("skip_reason", "model marked skip")})
            continue
        entry = {
            "title": str(cand.get("title") or "").strip(),
            "summary": str(cand.get("summary") or "").strip(),
            "content": str(cand.get("content") or "").strip(),
            "status": "candidate",
            "source_outcome": str(cand.get("source_outcome") or "unknown"),
        }
        if not entry["title"] or not entry["content"]:
            skipped.append({"index": idx, "reason": "missing title/content"})
            continue
        if not _sanitize(entry, domain):
            skipped.append({"index": idx, "reason": "failed sanitation (task-specific content)"})
            continue
        if _dedupe_by_title(entry, existing):
            skipped.append({"index": idx, "reason": f"title already in library: {entry['title']}"})
            continue
        entry["id"] = _next_id(domain, existing)
        existing.append(entry)
        imported.append(entry)

    if imported:
        with path.open("a", encoding="utf-8") as stream:
            for entry in imported:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(json.dumps({
        "ok": True,
        "domain": domain,
        "approved": len(approved_idx),
        "imported": imported,
        "skipped": skipped,
        "fail_source_imported": sum(1 for e in imported if str(e.get("source_outcome") or "").strip() == "fail"),
        "note_fail_source": "entries from FAILED tasks are provisional (hypothesis may be wrong); re-verify if any fail_source_imported > 0",
        "library_file": str(path),
        "library_total_after": len(existing),
    }, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manually import distilled candidates into the knowledge library")
    parser.add_argument("--input", required=True, help="distill draft file (logs/distill_pending/*_draft.json)")
    parser.add_argument("--domain", choices=list(KNOWLEDGE_DOMAINS), required=True, help="knowledge domain")
    parser.add_argument("--approve", default="", help="comma-separated candidate indices to import")
    parser.add_argument("--approve-all", action="store_true", help="import all non-skip, sanitized candidates")
    parser.add_argument("--list", action="store_true", help="only print the candidates, do not import")
    args = parser.parse_args(argv)

    if args.list:
        cmd_list(args)
    else:
        cmd_import(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
