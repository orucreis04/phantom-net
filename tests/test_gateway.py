import unittest
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, build_opener, urlopen

from phantom_net.detector import BehaviorDetector
from phantom_net.gateway import NoRedirectHandler, make_gateway_server
from phantom_net.models import Event
from phantom_net.storage import EventStore


class GatewayDecisionTests(unittest.TestCase):
    def test_low_risk_gateway_request_stays_observed(self):
        event = BehaviorDetector().enrich(
            Event(source_ip="10.0.0.10", service="gateway", event_type="gateway_request", path="/")
        )

        self.assertEqual(event.decision, "observe")
        self.assertNotIn("service_probe", event.tags)

    def test_sensitive_gateway_request_redirects_to_decoy(self):
        event = BehaviorDetector().enrich(
            Event(source_ip="10.0.0.10", service="gateway", event_type="gateway_request", path="/admin")
        )

        self.assertEqual(event.decision, "redirect_to_decoy")
        self.assertIn("sensitive_path", event.tags)


class BackendHandler(BaseHTTPRequestHandler):
    observed_headers = {}
    observed_body = b""

    def do_GET(self):
        BackendHandler.observed_headers = dict(self.headers)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/next")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = self.headers.get("X-Forwarded-For", "").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_HEAD(self):
        BackendHandler.observed_headers = dict(self.headers)
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        BackendHandler.observed_body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BackendHandler.observed_body)))
        self.end_headers()
        self.wfile.write(BackendHandler.observed_body)

    def log_message(self, format, *args):
        return


class GatewayProxyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        backend_url = f"http://127.0.0.1:{self.backend.server_address[1]}"
        store = EventStore(db_path=self._db_path())
        detector = BehaviorDetector(redirect_threshold=200)
        self.gateway = make_gateway_server("127.0.0.1", 0, 9999, store, detector, backend_url)
        self.gateway_thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.gateway_thread.start()
        self.base_url = f"http://127.0.0.1:{self.gateway.server_address[1]}"

    def tearDown(self):
        self.gateway.shutdown()
        self.backend.shutdown()
        self.gateway.server_close()
        self.backend.server_close()
        self.temp_dir.cleanup()

    def _db_path(self):
        return Path(self.temp_dir.name) / "events.sqlite3"

    def test_proxy_adds_forwarded_headers(self):
        request = Request(f"{self.base_url}/headers", headers={"X-Forwarded-For": "203.0.113.5"})
        body = urlopen(request, timeout=5).read().decode("utf-8")

        self.assertIn("203.0.113.5", body)
        self.assertIn("127.0.0.1", body)
        self.assertEqual(BackendHandler.observed_headers["X-Forwarded-Proto"], "http")
        self.assertIn("X-Forwarded-Host", BackendHandler.observed_headers)

    def test_proxy_does_not_follow_backend_redirects(self):
        opener = build_opener(NoRedirectHandler)
        with self.assertRaises(HTTPError) as raised:
            opener.open(f"{self.base_url}/redirect", timeout=5)

        self.assertEqual(raised.exception.code, 302)
        self.assertEqual(raised.exception.headers["Location"], "/next")

    def test_proxy_supports_head_and_put(self):
        head_request = Request(f"{self.base_url}/head", method="HEAD")
        head_response = urlopen(head_request, timeout=5)
        self.assertEqual(head_response.status, 204)

        put_request = Request(f"{self.base_url}/write", data=b"payload", method="PUT")
        put_response = urlopen(put_request, timeout=5)
        self.assertEqual(put_response.read(), b"payload")
        self.assertEqual(BackendHandler.observed_body, b"payload")


if __name__ == "__main__":
    unittest.main()
