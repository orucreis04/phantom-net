from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from phantom_net.siem import configure_siem, export_siem_event, siem_status


class SIEMTests(unittest.TestCase):
    def tearDown(self) -> None:
        configure_siem(True, "jsonl,cef,syslog", "data/siem_events.jsonl", "data/siem_cef.log", "data/siem_syslog.log")

    def test_exports_jsonl_cef_and_syslog(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            configure_siem(
                True,
                "jsonl,cef,syslog",
                str(base / "events.jsonl"),
                str(base / "events.cef"),
                str(base / "events.syslog"),
            )
            export_siem_event(
                {
                    "timestamp": "2026-05-24T12:00:00+00:00",
                    "session_id": "abc123",
                    "source_ip": "10.0.0.8",
                    "service": "gateway",
                    "event_type": "http_request",
                    "method": "GET",
                    "path": "/admin",
                    "payload": "password=[redacted]",
                    "risk_score": 85,
                    "decision": "redirect_to_decoy",
                    "tags": "sensitive_path,credential_attack",
                    "mitre_techniques": [{"id": "T1110", "name": "Brute Force"}],
                }
            )

            jsonl = (base / "events.jsonl").read_text(encoding="utf-8").strip()
            cef = (base / "events.cef").read_text(encoding="utf-8").strip()
            syslog = (base / "events.syslog").read_text(encoding="utf-8").strip()

        payload = json.loads(jsonl)
        self.assertEqual(payload["source_ip"], "10.0.0.8")
        self.assertEqual(payload["tags"], ["sensitive_path", "credential_attack"])
        self.assertIn("CEF:0|Phantom-Net|Deception Defense", cef)
        self.assertIn("src=10.0.0.8", cef)
        self.assertIn("<134>2026-05-24T12:00:00+00:00 phantom-net", syslog)

    def test_disabled_export_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "events.jsonl"
            configure_siem(True, "jsonl", str(target), str(target), str(target))
            configure_siem(False, "jsonl", str(target), str(target), str(target))
            export_siem_event({"source_ip": "10.0.0.8"})
            self.assertFalse(target.exists())
            self.assertFalse(siem_status()["enabled"])


if __name__ == "__main__":
    unittest.main()
