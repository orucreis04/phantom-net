import unittest

from phantom_net.mitre import enrich_event, techniques_for_tags


class MitreTests(unittest.TestCase):
    def test_techniques_are_mapped_from_tags(self):
        techniques = techniques_for_tags("credential_attack,sensitive_path,service_probe")
        ids = {technique["id"] for technique in techniques}

        self.assertIn("T1110", ids)
        self.assertIn("T1552", ids)
        self.assertIn("T1046", ids)

    def test_enrich_event_adds_mitre_techniques(self):
        event = enrich_event({"tags": "path_sweep"})

        self.assertEqual(event["mitre_techniques"][0]["id"], "T1083")
