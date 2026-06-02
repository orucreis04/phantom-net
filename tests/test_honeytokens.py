import unittest

from phantom_net.honeytokens import (
    fake_admin_users,
    fake_backup_catalog,
    fake_backup_manifest,
    fake_database_schema,
    fake_file_listing,
    fake_ftp_listing,
    fake_query_result,
    fake_slow_job,
    fake_terminal_response,
)


class HoneytokenTests(unittest.TestCase):
    def test_fake_file_listing_contains_decoy_paths(self):
        listing = fake_file_listing()

        self.assertEqual(listing["host"], "app-prod-02")
        self.assertTrue(any(".env" in item["path"] for item in listing["files"]))

    def test_fake_database_schema_and_query_result_are_coherent(self):
        schema = fake_database_schema()
        result = fake_query_result("select * from api_keys limit 5")

        self.assertEqual(schema["database"], "customer_ledger")
        self.assertEqual(result["table"], "api_keys")
        self.assertGreater(result["row_count"], 0)

    def test_fake_admin_users_and_backups_expose_decoy_inventory(self):
        users = fake_admin_users()
        backups = fake_backup_catalog()
        manifest = fake_backup_manifest("daily-prod-2026-05-23.tar.gz")

        self.assertTrue(any(user["username"] == "backup_svc" for user in users["users"]))
        self.assertTrue(any(item["status"] == "restricted" for item in backups["backups"]))
        self.assertIn("restorectl apply", manifest["restore_command"])

    def test_fake_slow_job_returns_pollable_status(self):
        job = fake_slow_job("/export/customer_export_2026_05.csv")

        self.assertIn("job", job)
        self.assertIn("estimated_seconds", job)
        self.assertEqual(job["path"], "/export/customer_export_2026_05.csv")

    def test_fake_terminal_and_ftp_decoys_are_available(self):
        terminal = fake_terminal_response("cat .env")
        ftp = fake_ftp_listing("/")

        self.assertIn("DB_PASSWORD", terminal["stdout"])
        self.assertTrue(any(entry["name"] == "database.dump.gz" for entry in ftp["entries"]))


if __name__ == "__main__":
    unittest.main()
