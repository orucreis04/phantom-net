from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from phantom_net.dashboard import make_dashboard_server
from phantom_net.storage import EventStore


class HealthEndpointTests(unittest.TestCase):
    def test_health_and_readiness_do_not_require_login(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(db_path=Path(temp_dir) / "events.sqlite3")
            server = make_dashboard_server("127.0.0.1", 0, store)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                health = json.loads(urlopen(f"{base_url}/healthz", timeout=5).read())
                ready = json.loads(urlopen(f"{base_url}/readyz", timeout=5).read())
            finally:
                server.shutdown()
                server.server_close()

        self.assertTrue(health["ok"])
        self.assertTrue(ready["ok"])
        self.assertIn("storage", ready)


if __name__ == "__main__":
    unittest.main()
