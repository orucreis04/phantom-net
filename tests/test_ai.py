import unittest

from phantom_net.ai import _extract_response_text, configure_ai, generate_decoy_data, summarize_activity


class AiAnalystTests(unittest.TestCase):
    def test_summarize_activity_produces_natural_language_findings(self):
        configure_ai("local", "gpt-5.2", "", 20)
        events = [
            {
                "source_ip": "10.0.0.4",
                "risk_score": 100,
                "decision": "redirect_to_decoy",
                "tags": "credential_attack,brute_force_pattern",
            },
            {
                "source_ip": "10.0.0.4",
                "risk_score": 90,
                "decision": "redirect_to_decoy",
                "tags": "credential_attack",
            },
        ]

        summary = summarize_activity(events, {"unique_sources": 1})

        self.assertEqual(summary["severity"], "critical")
        self.assertIn("10.0.0.4", summary["headline"])
        self.assertTrue(summary["key_findings"])
        self.assertTrue(summary["recommended_actions"])

    def test_generate_decoy_data_focuses_on_detected_behavior(self):
        configure_ai("local", "gpt-5.2", "", 20)
        decoy = generate_decoy_data(
            [
                {
                    "source_ip": "10.0.0.5",
                    "risk_score": 85,
                    "decision": "redirect_to_decoy",
                    "tags": "credential_attack,brute_force_pattern",
                }
            ]
        )

        self.assertEqual(decoy["focus"], "identity")
        self.assertIn("users", decoy["generated"])
        self.assertIn("recovery_code", decoy["generated"]["secrets"])

    def test_openai_response_text_extraction_supports_output_array(self):
        text = _extract_response_text(
            {
                "output": [
                    {
                        "content": [
                            {"type": "output_text", "text": "{\"severity\":\"low\"}"},
                        ]
                    }
                ]
            }
        )

        self.assertEqual(text, '{"severity":"low"}')


if __name__ == "__main__":
    unittest.main()
