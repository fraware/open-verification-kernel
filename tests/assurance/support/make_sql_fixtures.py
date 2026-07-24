"""Create offline SQLite fixtures for VA-10 tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "sql"


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    before = ROOT / "before.sqlite"
    after = ROOT / "after.sqlite"
    if before.is_file() and after.is_file():
        # Reuse existing fixtures (Windows may lock open sqlite handles).
        print(f"reuse {before} and {after}")
        return

    for path in (before, after):
        if path.exists():
            try:
                path.unlink()
            except OSError:
                print(f"could not unlink {path}; continuing")
                return

    conn = sqlite3.connect(before)
    conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO items(id, name) VALUES (1, 'a')")
    conn.commit()
    conn.close()

    conn = sqlite3.connect(after)
    conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO items(id, name) VALUES (1, 'a')")
    conn.execute("INSERT INTO items(id, name) VALUES (2, 'b')")
    conn.commit()
    conn.close()
    print(f"wrote {before} and {after}")


if __name__ == "__main__":
    main()
