import csv
import io
import json
import unittest

from phantom_net.reports import events_to_csv, events_to_json


class ReportExportTests(unittest.TestCase):
    def test_events_to_csv_includes_expected_columns(self):
        csv_payload = events_to_csv(
            [
                {
                    "id": 1,
                    "timestamp": "2026-05-24T10:00:00+00:00",
                    "source_ip": "10.0.0.2",
                    "service": "gateway",
                    "event_type": "gateway_request",
                    "method": "GET",
                    "path": "/admin",
                    "risk_score": 70,
                    "decision": "redirect_to_decoy",
                    "tags": "sensitive_path",
                }
            ]
        )

        rows = list(csv.DictReader(io.StringIO(csv_payload)))

        self.assertEqual(rows[0]["source_ip"], "10.0.0.2")
        self.assertEqual(rows[0]["decision"], "redirect_to_decoy")

    def test_events_to_json_wraps_event_list(self):
        payload = json.loads(events_to_json([{"id": 1, "source_ip": "10.0.0.2"}]))

        self.assertEqual(payload["events"][0]["id"], 1)


if __name__ == "__main__":
    unittest.main()
