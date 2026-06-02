from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .ai import generate_decoy_data, summarize_activity
from .auth import (
    clear_login_attempts,
    clear_session_cookie,
    csrf_token_from_cookie,
    is_authenticated,
    is_rate_limited,
    login_page,
    make_csrf_cookie,
    make_csrf_token,
    make_session_cookie,
    record_failed_login,
    verify_credentials,
    verify_csrf,
)
from .config import PROJECT_ROOT
from .reports import events_to_csv, events_to_json
from .siem import siem_status
from .storage import EventStore


class DashboardHandler(BaseHTTPRequestHandler):
    store: EventStore
    static_dir: Path = PROJECT_ROOT / "static"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/login":
            self._send_login_page()
        elif path == "/healthz":
            self._send_json({"ok": True, "service": "phantom-net"})
        elif path == "/readyz":
            health = self.store.health()
            status = HTTPStatus.OK if health.get("ok") else HTTPStatus.SERVICE_UNAVAILABLE
            self._send_json({"ok": bool(health.get("ok")), "service": "phantom-net", "storage": health}, status)
        elif path == "/logout":
            self.store.add_admin_audit(self._source_ip(), "logout", "success")
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", clear_session_cookie())
            self.end_headers()
        elif not self._is_authenticated():
            self._redirect_to_login()
        elif path == "/" or path.startswith("/index.html"):
            self._send_file(self.static_dir / "index.html", "text/html; charset=utf-8")
        elif path == "/styles.css":
            self._send_file(self.static_dir / "styles.css", "text/css; charset=utf-8")
        elif path == "/app.js":
            self._send_file(self.static_dir / "app.js", "application/javascript; charset=utf-8")
        elif path.startswith("/api/stats"):
            self._send_json(self.store.stats())
        elif path.startswith("/api/events"):
            self._send_json(
                {
                    "events": self.store.events(
                        limit=self._int_param(params, "limit", 100),
                        source_ip=self._str_param(params, "source_ip"),
                        decision=self._str_param(params, "decision"),
                        min_risk=self._optional_int_param(params, "min_risk"),
                    )
                }
            )
        elif path.startswith("/api/sources/"):
            source_ip = unquote(path.removeprefix("/api/sources/"))
            self._send_json(self.store.source_detail(source_ip, limit=self._int_param(params, "limit", 100)))
        elif path.startswith("/api/reports/summary"):
            self._send_json(
                self.store.attack_summary(
                    period=self._str_param(params, "period") or "daily",
                    limit=self._int_param(params, "limit", 14),
                )
            )
        elif path.startswith("/api/reports/export"):
            self._send_export(params)
        elif path.startswith("/api/ai/summary"):
            events = self.store.events(limit=self._int_param(params, "limit", 150))
            self._send_json(summarize_activity(events, self.store.stats()))
        elif path.startswith("/api/ai/decoy-data"):
            events = self.store.events(limit=self._int_param(params, "limit", 150))
            self._send_json(generate_decoy_data(events))
        elif path.startswith("/api/ai/reports"):
            self._send_json({"reports": self.store.ai_reports(limit=self._int_param(params, "limit", 20))})
        elif path.startswith("/api/ai/report"):
            events = self.store.events(limit=self._int_param(params, "limit", 150))
            summary = summarize_activity(events, self.store.stats())
            decoy_data = generate_decoy_data(events)
            self.store.add_admin_audit(self._source_ip(), "ai_report_save", "success", summary.get("headline", ""))
            self._send_json(self.store.save_ai_report(summary, decoy_data))
        elif path.startswith("/api/admin/audit"):
            self._send_json({"audit": self.store.admin_audit(limit=self._int_param(params, "limit", 100))})
        elif path.startswith("/api/siem/status"):
            self._send_json(siem_status())
        elif path.startswith("/api/incidents"):
            self._send_json(
                {
                    "incidents": self.store.incidents(
                        limit=self._int_param(params, "limit", 50),
                        status=self._str_param(params, "status"),
                    )
                }
            )
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self._handle_login()
            return
        if not self._is_authenticated():
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        if parsed.path == "/api/incidents/create":
            self._handle_incident_create()
            return
        if parsed.path == "/api/incidents/update":
            self._handle_incident_update()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_login(self) -> None:
        source_ip = self._source_ip()
        body = self._read_body()
        if is_rate_limited(source_ip):
            self.store.add_admin_audit(source_ip, "login", "blocked", "too many attempts")
            self._send_login_page("Too many failed attempts. Try again later.", HTTPStatus.TOO_MANY_REQUESTS)
        elif not verify_csrf(self.headers.get("Cookie"), body):
            self.store.add_admin_audit(source_ip, "login", "denied", "csrf failed")
            self._send_login_page("Session token expired. Try again.", HTTPStatus.FORBIDDEN)
        elif verify_credentials(body):
            clear_login_attempts(source_ip)
            self.store.add_admin_audit(source_ip, "login", "success")
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", make_session_cookie())
            self.end_headers()
        else:
            record_failed_login(source_ip)
            self.store.add_admin_audit(source_ip, "login", "denied", "invalid credentials")
            self._send_login_page("Invalid username or password.", HTTPStatus.UNAUTHORIZED)

    def _handle_incident_create(self) -> None:
        fields = parse_qs(self._read_body())
        source_ip = fields.get("source_ip", [""])[0].strip()
        if not source_ip:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        incident = self.store.create_incident(
            source_ip=source_ip,
            title=fields.get("title", [""])[0].strip(),
            severity=fields.get("severity", ["high"])[0].strip() or "high",
            analyst_note=fields.get("analyst_note", [""])[0].strip(),
        )
        self.store.add_admin_audit(self._source_ip(), "incident_create", "success", f"incident={incident['id']}")
        self._send_json({"incident": incident}, HTTPStatus.CREATED)

    def _handle_incident_update(self) -> None:
        fields = parse_qs(self._read_body())
        try:
            incident_id = int(fields.get("id", ["0"])[0])
        except ValueError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        incident = self.store.update_incident(
            incident_id,
            status=fields.get("status", [""])[0].strip() or None,
            severity=fields.get("severity", [""])[0].strip() or None,
            analyst_note=fields.get("analyst_note", [None])[0],
        )
        if not incident:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.store.add_admin_audit(self._source_ip(), "incident_update", "success", f"incident={incident['id']}")
        self._send_json({"incident": incident})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_file(self, path: Path, content_type: str) -> None:
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

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

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length).decode("utf-8", errors="replace")[:4000]

    def _is_authenticated(self) -> bool:
        return is_authenticated(self.headers.get("Cookie"))

    def _send_login_page(self, error: str = "", status: HTTPStatus = HTTPStatus.OK) -> None:
        token = csrf_token_from_cookie(self.headers.get("Cookie")) or make_csrf_token()
        data = login_page(token, error).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Set-Cookie", make_csrf_cookie(token))
        self.end_headers()
        self.wfile.write(data)

    def _source_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        return forwarded or self.client_address[0]

    def _redirect_to_login(self) -> None:
        if self.path.startswith("/api/"):
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", "/login")
        self.end_headers()

    def _send_export(self, params: dict[str, list[str]]) -> None:
        events = self.store.events(
            limit=self._int_param(params, "limit", 500),
            source_ip=self._str_param(params, "source_ip"),
            decision=self._str_param(params, "decision"),
            min_risk=self._optional_int_param(params, "min_risk"),
        )
        export_format = self._str_param(params, "format") or "json"
        if export_format == "csv":
            data = events_to_csv(events).encode("utf-8")
            content_type = "text/csv; charset=utf-8"
            filename = "phantom-net-events.csv"
        else:
            data = events_to_json(events).encode("utf-8")
            content_type = "application/json; charset=utf-8"
            filename = "phantom-net-events.json"

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _str_param(self, params: dict[str, list[str]], name: str) -> str | None:
        value = params.get(name, [""])[0].strip()
        return value or None

    def _int_param(self, params: dict[str, list[str]], name: str, default: int) -> int:
        value = self._optional_int_param(params, name)
        return default if value is None else max(1, min(value, 500))

    def _optional_int_param(self, params: dict[str, list[str]], name: str) -> int | None:
        raw = params.get(name, [""])[0].strip()
        if not raw:
            return None
        try:
            return int(raw)
        except ValueError:
            return None


def make_dashboard_server(host: str, port: int, store: EventStore) -> ThreadingHTTPServer:
    handler = type("ConfiguredDashboardHandler", (DashboardHandler,), {"store": store})
    return ThreadingHTTPServer((host, port), handler)
