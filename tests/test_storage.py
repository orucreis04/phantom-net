import unittest

from phantom_net.models import Event
from phantom_net.storage import EventStore


class StorageTests(unittest.TestCase):
    def test_event_store_persists_and_summarizes_events(self):
        with self.subTest("sqlite event lifecycle"):
            from tempfile import TemporaryDirectory
            from pathlib import Path

            with TemporaryDirectory() as tmpdir:
                store = EventStore(Path(tmpdir) / "events.sqlite3")
                store.add_event(
                    Event(
                        source_ip="127.0.0.1",
                        service="web",
                        event_type="auth_attempt",
                        path="/login",
                        risk_score=80,
                        decision="redirect_to_decoy",
                        tags=["credential_attack"],
                    )
                )

                events = store.recent_events()
                stats = store.stats()

                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["source_ip"], "127.0.0.1")
                self.assertEqual(stats["total_events"], 1)
                self.assertEqual(stats["high_risk_events"], 1)
                self.assertEqual(stats["redirected_sessions"], 1)

    def test_event_store_redacts_sensitive_payload_fields(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmpdir:
            store = EventStore(Path(tmpdir) / "events.sqlite3")
            store.add_event(
                Event(
                    source_ip="127.0.0.1",
                    service="web",
                    event_type="auth_attempt",
                    path="/login",
                    payload="username=admin&password=123456&token=abc",
                )
            )

            payload = store.recent_events()[0]["payload"]

            self.assertIn("username=admin", payload)
            self.assertIn("password=%5Bredacted%5D", payload)
            self.assertIn("token=%5Bredacted%5D", payload)
            self.assertNotIn("123456", payload)

    def test_event_filters_and_source_detail(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmpdir:
            store = EventStore(Path(tmpdir) / "events.sqlite3")
            store.add_event(
                Event(
                    source_ip="10.0.0.5",
                    service="gateway",
                    event_type="gateway_request",
                    path="/admin",
                    risk_score=70,
                    decision="redirect_to_decoy",
                    tags=["sensitive_path"],
                )
            )
            store.add_event(
                Event(
                    source_ip="10.0.0.6",
                    service="web",
                    event_type="http_request",
                    path="/",
                    risk_score=5,
                    decision="observe",
                )
            )

            filtered = store.events(source_ip="10.0.0.5", decision="redirect_to_decoy", min_risk=35)
            detail = store.source_detail("10.0.0.5")

            self.assertEqual(len(filtered), 1)
            self.assertEqual(detail["summary"]["source_ip"], "10.0.0.5")
            self.assertEqual(detail["summary"]["redirected_events"], 1)
            self.assertEqual(detail["services"][0]["service"], "gateway")
            self.assertEqual(detail["tags"][0]["tag"], "sensitive_path")

    def test_attack_summary_groups_periods_and_risky_ips(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmpdir:
            store = EventStore(Path(tmpdir) / "events.sqlite3")
            store.add_event(
                Event(
                    timestamp="2026-05-24T08:00:00+00:00",
                    source_ip="10.0.0.7",
                    service="gateway",
                    event_type="gateway_request",
                    path="/admin",
                    risk_score=85,
                    decision="redirect_to_decoy",
                    tags=["sensitive_path", "session_memory"],
                )
            )
            store.add_event(
                Event(
                    timestamp="2026-05-24T09:00:00+00:00",
                    source_ip="10.0.0.8",
                    service="web",
                    event_type="http_request",
                    path="/",
                    risk_score=5,
                    decision="observe",
                )
            )

            daily = store.attack_summary("daily")
            weekly = store.attack_summary("weekly")

            self.assertEqual(daily["period"], "daily")
            self.assertEqual(daily["buckets"][0]["bucket"], "2026-05-24")
            self.assertEqual(daily["buckets"][0]["total_events"], 2)
            self.assertEqual(daily["risky_ips"][0]["source_ip"], "10.0.0.7")
            self.assertEqual(daily["attack_types"][0]["type"], "sensitive_path")
            self.assertEqual(weekly["period"], "weekly")
            self.assertTrue(weekly["buckets"][0]["bucket"].startswith("2026-W"))

    def test_ai_reports_are_persisted(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmpdir:
            store = EventStore(Path(tmpdir) / "events.sqlite3")
            saved = store.save_ai_report(
                {"severity": "high", "headline": "Test headline", "summary": "Test summary"},
                {"focus": "identity"},
            )
            reports = store.ai_reports()

            self.assertEqual(saved["id"], 1)
            self.assertEqual(reports[0]["severity"], "high")
            self.assertEqual(reports[0]["payload"]["decoy_data"]["focus"], "identity")

    def test_admin_audit_is_persisted(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmpdir:
            store = EventStore(Path(tmpdir) / "events.sqlite3")
            store.add_admin_audit("127.0.0.1", "login", "success", "test")
            audit = store.admin_audit()

            self.assertEqual(audit[0]["source_ip"], "127.0.0.1")
            self.assertEqual(audit[0]["action"], "login")
            self.assertEqual(audit[0]["status"], "success")

    def test_incidents_are_created_with_mitre_context(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as tmpdir:
            store = EventStore(Path(tmpdir) / "events.sqlite3")
            store.add_event(
                Event(
                    source_ip="10.0.0.9",
                    service="web",
                    event_type="auth_attempt",
                    path="/login",
                    risk_score=90,
                    decision="redirect_to_decoy",
                    tags=["credential_attack", "brute_force_pattern"],
                )
            )

            incident = store.create_incident("10.0.0.9")
            updated = store.update_incident(incident["id"], status="resolved", analyst_note="contained")

            self.assertEqual(incident["source_ip"], "10.0.0.9")
            self.assertEqual(incident["mitre_techniques"][0]["id"], "T1110")
            self.assertEqual(updated["status"], "resolved")
            self.assertEqual(store.incidents()[0]["analyst_note"], "contained")


if __name__ == "__main__":
    unittest.main()
