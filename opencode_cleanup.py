#!/usr/bin/env python3
"""Batch-end cleanup for opencode's local database.

Deletes the automated batch/reflect/distill sessions (full transcripts are
already archived under logs/batch_*/<task>/), clears the `event` audit table
(the main source of DB bloat — event rows are NOT cascade-deleted with
sessions), then compacts the file via `VACUUM INTO` + atomic replace.

Why VACUUM INTO instead of VACUUM: a plain VACUUM does not reliably shrink the
file in WAL mode here; VACUUM INTO writes a compact copy that we integrity-check
before atomically replacing the live DB. If anything fails, the original DB is
left untouched.

Run only while no opencode session is active (i.e. at batch end / between
batches). Configuration lives in opencode.json / config.toml.local (files),
not in the DB, so nothing mission-critical is removed.
"""
import os
import shutil
import sqlite3
import sys

DB = os.path.expanduser("~/.local/share/opencode/opencode.db")
COMPACT = DB + ".compact"


def _fail(msg: str) -> None:
    print(f"cleanup: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    if not os.path.exists(DB):
        print("cleanup: no opencode db at", DB)
        return 0
    before = os.path.getsize(DB)

    con = sqlite3.connect(DB, timeout=600)
    con.execute("PRAGMA foreign_keys=ON")
    try:
        nsess = con.execute(
            "DELETE FROM session WHERE title LIKE 'batch-%' OR title LIKE 'reflect-%' OR title LIKE 'distill-%'"
        ).rowcount
        con.execute("DELETE FROM event")
        con.commit()
        if os.path.exists(COMPACT):
            os.remove(COMPACT)
        con.execute("VACUUM INTO ?", (COMPACT,))
        con.commit()
    except sqlite3.Error as exc:
        con.close()
        _fail(f"database operation failed (left original intact): {exc}")
    con.close()

    if not os.path.exists(COMPACT):
        _fail("compact copy was not produced; original untouched")
    try:
        check = sqlite3.connect(COMPACT)
        status = check.execute("PRAGMA integrity_check").fetchone()[0]
        n_sess = check.execute("SELECT COUNT(*) FROM session").fetchone()[0]
        check.close()
    except sqlite3.Error as exc:
        _fail(f"compact copy unreadable: {exc}")
    if status != "ok":
        os.remove(COMPACT)
        _fail(f"compact copy integrity failed ({status!r}); original untouched")

    # Atomic replace, then drop any stale WAL/SHM sidecars of the old file.
    os.replace(COMPACT, DB)
    for side in (DB + "-wal", DB + "-shm"):
        if os.path.exists(side):
            os.remove(side)
    after = os.path.getsize(DB)
    print(
        f"cleanup: deleted {nsess} automated sessions, cleared event table; "
        f"opencode.db {before / 1e9:.2f}GB -> {after / 1e6:.1f}MB "
        f"(sessions kept: {n_sess})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
