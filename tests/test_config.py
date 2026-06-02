import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from phantom_net.config import load_config, validate_config


class ConfigTests(unittest.TestCase):
    def test_load_config_file_overrides_defaults(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"
            path.write_text(
                """
profile: lab
server:
  host: 0.0.0.0
  dashboard_port: 8090
  no_tcp_decoys: true
auth:
  password_hash: pbkdf2_sha256$1$salt$digest
  max_login_attempts: 3
detector:
  redirect_threshold: 45
alerts:
  threshold: 80
ai:
  provider: openai
  model: gpt-5.2
  timeout_seconds: 9
rules:
  - name: custom_recent
    condition: recent_hits_gte:2
    tag: custom_recent
    score: 10
    enabled: true
""",
                encoding="utf-8",
            )

            config = load_config(path)

            self.assertEqual(config.profile, "lab")
            self.assertEqual(config.server.host, "0.0.0.0")
            self.assertEqual(config.server.dashboard_port, 8090)
            self.assertTrue(config.server.no_tcp_decoys)
            self.assertEqual(config.auth.password_hash, "pbkdf2_sha256$1$salt$digest")
            self.assertEqual(config.auth.max_login_attempts, 3)
            self.assertEqual(config.detector.redirect_threshold, 45)
            self.assertEqual(config.alerts.threshold, 80)
            self.assertEqual(config.ai.provider, "openai")
            self.assertEqual(config.ai.model, "gpt-5.2")
            self.assertEqual(config.ai.timeout_seconds, 9)
            self.assertEqual(config.rules[0]["name"], "custom_recent")

    def test_environment_overrides_config_file(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"
            path.write_text("server:\n  dashboard_port: 8090\n", encoding="utf-8")
            os.environ["PHANTOM_DASHBOARD_PORT"] = "9000"
            try:
                config = load_config(path)
            finally:
                os.environ.pop("PHANTOM_DASHBOARD_PORT", None)

            self.assertEqual(config.server.dashboard_port, 9000)

    def test_production_config_rejects_default_secret_and_password(self):
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"
            path.write_text("profile: production\n", encoding="utf-8")
            previous_secret = os.environ.pop("PHANTOM_AUTH_SECRET", None)
            try:
                errors, warnings = validate_config(load_config(path))
            finally:
                if previous_secret is not None:
                    os.environ["PHANTOM_AUTH_SECRET"] = previous_secret

            self.assertTrue(any("default admin password" in error for error in errors))
            self.assertTrue(any("auth.secret" in error for error in errors))
            self.assertTrue(any("password_hash" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
