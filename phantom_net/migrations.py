from __future__ import annotations

import sqlite3
from pathlib import Path


MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def run_migrations(conn: sqlite3.Connection, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    applied = {
        row[0]
        for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    }
    applied_now: list[str] = []
    for path in sorted(migrations_dir.glob("*.sql")):
        version = path.stem
        if version in applied:
            continue
        conn.executescript(path.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO schema_migrations (version) VALUES (?)", (version,))
        applied_now.append(version)
    return applied_now


def applied_migrations(conn: sqlite3.Connection) -> list[str]:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    rows = conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    return [row[0] for row in rows]
