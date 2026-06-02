from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import sleep
from urllib.parse import parse_qs, urlparse

from .detector import BehaviorDetector
from .honeytokens import (
    fake_admin_users,
    fake_backup_catalog,
    fake_backup_manifest,
    fake_dashboard_state,
    fake_database_schema,
    fake_file_listing,
    fake_ftp_listing,
    fake_query_result,
    fake_secret_bundle,
    fake_slow_job,
    fake_terminal_response,
)
from .models import Event
from .storage import EventStore


LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Enterprise Admin Console</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: Arial, sans-serif; background: #f4f7fb; color: #1c2633; }
    main { width: min(420px, calc(100vw - 32px)); border: 1px solid #d8e0ea; background: white; padding: 28px; border-radius: 8px; box-shadow: 0 14px 40px rgba(24, 39, 75, .10); }
    label { display: block; margin: 14px 0 6px; font-size: 14px; }
    input { width: 100%; box-sizing: border-box; border: 1px solid #b9c4d0; border-radius: 6px; padding: 11px; }
    button { width: 100%; margin-top: 18px; padding: 11px; border: 0; border-radius: 6px; background: #1f6feb; color: white; font-weight: 700; }
    .hint { color: #637083; font-size: 13px; }
  </style>
</head>
<body>
  <main>
    <h1>Admin Console</h1>
    <p class="hint">Authorized operations only.</p>
    <form method="post" action="/login">
      <label>Username</label><input name="username" autocomplete="username">
      <label>Password</label><input name="password" type="password" autocomplete="current-password">
      <button>Sign in</button>
    </form>
  </main>
</body>
</html>"""


TERMINAL_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Remote Shell</title>
  <style>
    body { margin: 0; background: #101820; color: #d7e2ee; font-family: monospace; }
    main { padding: 24px; }
    input { width: 100%; padding: 10px; background: #172434; color: #d7e2ee; border: 1px solid #33485f; border-radius: 6px; }
    pre { white-space: pre-wrap; }
  </style>
</head>
<body>
  <main>
    <h1>app-prod-02:/srv/app/current</h1>
    <form method="post" action="/api/terminal/run"><input name="cmd" value="help"></form>
    <pre>Connected to maintenance shell. Session latency is elevated.</pre>
  </main>
</body>
</html>"""


class HoneypotHandler(BaseHTTPRequestHandler):
    store: EventStore
    detector: BehaviorDetector
    response_delay_seconds: float = 0.35

    def do_GET(self) -> None:
        self._record("http_request")
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/admin", "/admin/", "/wp-login.php"):
            self._send_html(LOGIN_PAGE)
        elif path.startswith("/api/users"):
            self._send_json(fake_dashboard_state())
        elif path in ("/admin/users", "/api/admin/users"):
            self._send_json(fake_admin_users())
        elif path in ("/files", "/api/files", "/var/www/html", "/srv/app"):
            self._send_json(fake_file_listing())
        elif path in ("/api/db/tables", "/db/tables", "/database/schema"):
            self._send_json(fake_database_schema())
        elif path.startswith("/api/db/query") or path.startswith("/db/query"):
            query = parse_qs(parsed.query).get("q", ["select * from users limit 10"])[0]
            self._delay()
            self._send_json(fake_query_result(query))
        elif path in ("/backup", "/backup/", "/backups", "/api/backups"):
            self._send_json(fake_backup_catalog())
        elif path.startswith("/backup/") or path.startswith("/api/backups/"):
            name = path.rsplit("/", 1)[-1]
            self._delay()
            self._send_json(fake_backup_manifest(name))
        elif path.startswith("/download") or path.startswith("/export"):
            self._delay()
            self._send_json(fake_slow_job(path), HTTPStatus.ACCEPTED)
        elif path in ("/ftp", "/ftp/", "/api/ftp"):
            self._send_json(fake_ftp_listing(path))
        elif path in ("/terminal", "/shell", "/api/terminal"):
            self._send_html(TERMINAL_PAGE)
        elif path.startswith("/api/terminal/run"):
            command = parse_qs(parsed.query).get("cmd", ["help"])[0]
            self._delay()
            self._send_json(fake_terminal_response(command))
        elif path.startswith("/.env"):
            self._send_json(fake_secret_bundle())
        elif path == "/robots.txt":
            self._send_text("Disallow: /admin\nDisallow: /backup\nDisallow: /api/db\nDisallow: /files\n")
        else:
            self._send_html(LOGIN_PAGE, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        body = self._read_body()
        fields = parse_qs(body)
        parsed = urlparse(self.path)
        path = parsed.path
        event_type = "auth_attempt" if path in ("/login", "/admin", "/wp-login.php") else "http_post"
        self._record(event_type, body)
        if path in ("/api/db/query", "/db/query"):
            query = fields.get("q", fields.get("query", ["select * from users limit 10"]))[0]
            self._delay()
            self._send_json(fake_query_result(query))
        elif path in ("/api/terminal/run", "/terminal/run", "/shell/run"):
            command = fields.get("cmd", fields.get("command", ["help"]))[0]
            self._delay()
            self._send_json(fake_terminal_response(command))
        elif path.startswith("/backup/restore") or path.startswith("/export"):
            self._delay()
            self._send_json(fake_slow_job(path), HTTPStatus.ACCEPTED)
        elif fields:
            self._send_html("<h1>Maintenance mode</h1><p>Retry later.</p>", HTTPStatus.UNAUTHORIZED)
        else:
            self._send_json({"status": "queued", "ticket": "PNET-INC-2048"})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length).decode("utf-8", errors="replace")[:4000]

    def _record(self, event_type: str, payload: str = "") -> None:
        forwarded = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        source_ip = forwarded or self.client_address[0]
        event = Event(
            source_ip=source_ip,
            service="web",
            event_type=event_type,
            method=self.command,
            path=self.path,
            payload=payload,
            user_agent=self.headers.get("User-Agent", ""),
        )
        self.store.add_event(self.detector.enrich(event))

    def _delay(self) -> None:
        sleep(self.response_delay_seconds)

    def _send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, body: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_honeypot_server(
    host: str,
    port: int,
    store: EventStore,
    detector: BehaviorDetector,
    response_delay_seconds: float = 0.35,
) -> ThreadingHTTPServer:
    handler = type(
        "ConfiguredHoneypotHandler",
        (HoneypotHandler,),
        {"store": store, "detector": detector, "response_delay_seconds": response_delay_seconds},
    )
    return ThreadingHTTPServer((host, port), handler)
