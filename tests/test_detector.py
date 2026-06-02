import unittest

from phantom_net.detector import BehaviorDetector
from phantom_net.models import Event
from phantom_net.rules import Rule


class DetectorTests(unittest.TestCase):
    def test_sensitive_admin_path_is_redirected_to_decoy(self):
        detector = BehaviorDetector()
        event = detector.enrich(Event(source_ip="10.0.0.8", service="web", event_type="http_request", path="/admin"))

        self.assertGreaterEqual(event.risk_score, 35)
        self.assertEqual(event.decision, "redirect_to_decoy")
        self.assertIn("sensitive_path", event.tags)

    def test_multi_service_probe_is_classified_as_port_scan(self):
        detector = BehaviorDetector()
        detector.enrich(Event(source_ip="10.0.0.9", service="ssh", event_type="tcp_probe"))
        detector.enrich(Event(source_ip="10.0.0.9", service="mysql", event_type="tcp_probe"))
        event = detector.enrich(Event(source_ip="10.0.0.9", service="postgres", event_type="tcp_probe"))

        self.assertGreaterEqual(event.risk_score, 70)
        self.assertIn("port_scan", event.tags)
        self.assertEqual(event.decision, "redirect_to_decoy")

    def test_rate_limit_flags_short_burst_from_same_ip(self):
        detector = BehaviorDetector()
        event = None

        for _ in range(detector.rate_limit_hits):
            event = detector.enrich(Event(source_ip="10.0.0.11", service="gateway", event_type="gateway_request", path="/"))

        self.assertIsNotNone(event)
        self.assertIn("rate_limit_exceeded", event.tags)
        self.assertEqual(event.decision, "redirect_to_decoy")

    def test_path_history_flags_directory_sweep(self):
        detector = BehaviorDetector()
        event = None

        for path in ("/", "/status", "/assets", "/health", "/old"):
            event = detector.enrich(
                Event(source_ip="10.0.0.12", service="gateway", event_type="gateway_request", path=path)
            )

        self.assertIsNotNone(event)
        self.assertIn("path_sweep", event.tags)
        self.assertEqual(event.decision, "redirect_to_decoy")

    def test_high_risk_session_memory_affects_later_gateway_request(self):
        detector = BehaviorDetector()
        detector.enrich(Event(source_ip="10.0.0.13", service="ssh", event_type="tcp_probe"))
        detector.enrich(Event(source_ip="10.0.0.13", service="mysql", event_type="tcp_probe"))
        detector.enrich(Event(source_ip="10.0.0.13", service="postgres", event_type="tcp_probe"))

        event = detector.enrich(
            Event(source_ip="10.0.0.13", service="gateway", event_type="gateway_request", path="/")
        )

        self.assertIn("session_memory", event.tags)
        self.assertEqual(event.decision, "redirect_to_decoy")

    def test_custom_rule_can_change_detector_behavior(self):
        detector = BehaviorDetector(
            redirect_threshold=20,
            rules=[Rule("custom_recent", "recent_hits_gte:2", "custom_recent", 20)],
        )
        detector.enrich(Event(source_ip="10.0.0.14", service="gateway", event_type="gateway_request", path="/"))
        event = detector.enrich(Event(source_ip="10.0.0.14", service="gateway", event_type="gateway_request", path="/"))

        self.assertIn("custom_recent", event.tags)
        self.assertEqual(event.decision, "redirect_to_decoy")


if __name__ == "__main__":
    unittest.main()
