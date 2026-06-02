import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from phantom_net.migrations import applied_migrations, run_migrations
from phantom_net.storage import EventStore


class MigrationTests(unittest.TestCase):
    def test_run_migrations_is_idempotent(self):
        with TemporaryDirectory() as tmpdir:
            migrations_dir = Path(tmpdir) / "migrations"
            migrations_dir.mkdir()
            (migrations_dir / "001_test.sql").write_text(
                "CREATE TABLE sample (id INTEGER PRIMARY KEY);",
                encoding="utf-8",
            )
            conn = sqlite3.connect(Path(tmpdir) / "db.sqlite3")

            first = run_migrations(conn, migrations_dir)
            second = run_migrations(conn, migrations_dir)

            self.assertEqual(first, ["001_test"])
            self.assertEqual(second, [])
            self.assertEqual(applied_migrations(conn), ["001_test"])

    def test_event_store_applies_initial_schema_migration(self):
        with TemporaryDirectory() as tmpdir:
            store = EventStore(Path(tmpdir) / "events.sqlite3")

            versions = store.migration_versions()

            self.assertIn("001_initial_schema", versions)
            self.assertIn("002_incidents", versions)


if __name__ == "__main__":
    unittest.main()
