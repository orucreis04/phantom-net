import unittest

from phantom_net.rules import Rule, RuleEngine, rules_from_config


class RuleEngineTests(unittest.TestCase):
    def test_rule_engine_applies_matching_rule(self):
        engine = RuleEngine([Rule("admin_path", "haystack_contains:suspicious_path_hints", "sensitive_path", 30)])

        score, tags = engine.evaluate(
            {
                "base_score": 5,
                "haystack": "/admin",
                "suspicious_path_hints": ("admin",),
            }
        )

        self.assertEqual(score, 35)
        self.assertEqual(tags, ["sensitive_path"])

    def test_disabled_rule_is_ignored(self):
        engine = RuleEngine([Rule("disabled", "decoy_locked", "decoy_session", 20, enabled=False)])

        score, tags = engine.evaluate({"base_score": 5, "decoy_locked": True})

        self.assertEqual(score, 5)
        self.assertEqual(tags, [])

    def test_rules_from_config_maps_dicts(self):
        rules = rules_from_config(
            [
                {
                    "name": "custom",
                    "condition": "recent_hits_gte:2",
                    "tag": "custom_tag",
                    "score": 10,
                    "enabled": True,
                }
            ]
        )

        self.assertEqual(rules[0].name, "custom")
        self.assertEqual(rules[0].condition, "recent_hits_gte:2")
        self.assertEqual(rules[0].tag, "custom_tag")


if __name__ == "__main__":
    unittest.main()
