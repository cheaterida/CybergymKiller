"""Experience knowledge base: read-only list/read for the main research agent.

Two simple JSONL libraries (reasoning / format), each entry is a reviewed,
sanitized natural-language experience record (id / title / summary / content /
status). The base stores only what an offline maintenance process wrote; the
agent reads via `knowledge_list <domain>` and `knowledge_read <entry_id>`.

Per design (docs/GLOBAL-RESEARCH-CHAIN-UPGRADE-THINKING.md §5.4): no complex
feature retrieval, no embeddings, no per-task lookup. Entries never contain task
ids, PoC bytes, construction scripts, fix/patch or Level-3 internals — the
sanitization guarantee lives in the offline maintenance writer, this module only
returns what the file holds. Empty or unknown entries degrade transparently.
"""
from __future__ import annotations

import json
from pathlib import Path

from config import KNOWLEDGE_HOME, KNOWLEDGE_DOMAINS

# Advisory shown alongside any experience the agent reads. Experience is mined
# from OTHER tasks: different projects may share similar source/format, so an
# entry is a HINT, never ground truth for the current task. The agent must
# weigh it against current-task evidence and discard what does not fit.
CAVEAT = (
    "NOTE: these entries are mined from OTHER tasks. Different tasks may share "
    "the same or similar source project / format, so an entry is a HINT to "
    "consider, never a fact about this task — verify it against THIS task's "
    "source, harness and experiments before adopting it, and ignore it if it "
    "does not fit. Entries whose source_outcome is 'fail' are PROVISIONAL: they "
    "came from an unsolved task and may encode a wrong hypothesis — treat them "
    "with extra skepticism and validate any mechanism claim against this task's "
    "own evidence."
)


def _domain_path(domain: str) -> Path:
    return Path(KNOWLEDGE_HOME) / domain / "entries.jsonl"


def valid_domain(domain: str) -> bool:
    return str(domain or "").strip() in KNOWLEDGE_DOMAINS


def list_entries(domain: str) -> list[dict]:
    """Return the entry list (id/title/summary only — never full content)."""
    domain = str(domain or "").strip()
    if not valid_domain(domain):
        return []
    path = _domain_path(domain)
    if not path.is_file():
        return []
    entries: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                entries.append({
                    "id": str(record.get("id") or ""),
                    "title": str(record.get("title") or ""),
                    "summary": str(record.get("summary") or ""),
                    "status": str(record.get("status") or "candidate"),
                })
    except OSError:
        return []
    return entries


def read_entry(domain: str, entry_id: str) -> str | None:
    """Return one entry's full natural-language content, or None if missing."""
    domain = str(domain or "").strip()
    entry_id = str(entry_id or "").strip()
    if not valid_domain(domain) or not entry_id:
        return None
    path = _domain_path(domain)
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict) and str(record.get("id") or "") == entry_id:
                    title = str(record.get("title") or "")
                    content = str(record.get("content") or "")
                    status = str(record.get("status") or "")
                    body = f"[{domain}] {title} (status: {status})\n{content}\n\n{CAVEAT}"
                    return body.strip()
    except OSError:
        return None
    return None


def render_list(domain: str) -> str:
    """Render a human-readable listing for the agent."""
    entries = list_entries(domain)
    if not entries:
        return f"## {domain} experience\n(none yet — no reviewed entries available)"
    lines = [
        f"## {domain} experience",
        "Review the list and choose what is relevant.",
        CAVEAT,
    ]
    for e in entries:
        status = e.get("status") or "candidate"
        lines.append(f"- {e.get('id')}: {e.get('title')} ({status}) — {e.get('summary')}")
    return "\n".join(lines)
