from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .detector import BehaviorDetector
from .models import Event
from .storage import EventStore


REAL_APP_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protected App</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; font-family: Arial, sans-serif; background: #f3f6fa; color: #1d2733; }
    main { width: min(680px, calc(100vw - 32px)); }
    h1 { font-size: 28px; margin-bottom: 8px; }
    p { color: #607086; line-height: 1.5; }
  </style>
</head>
<body>
  <main>
    <h1>Protected Business Application</h1>
    <p>This placeholder represents the real service. Low-risk requests stay here; suspicious activity is redirected into the decoy environment.</p>
  </main>
</body>
</html>"""


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
MAX_PROXY_BODY_BYTES = 1_000_000


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class GatewayHandler(BaseHTTPRequestHandler):
    store: EventStore
    detector: BehaviorDetector
    honeypot_url: str
    backend_url: str = ""

    def do_GET(self) -> None:
        self._handle_gateway_request("gateway_request")

    def do_HEAD(self) -> None:
        self._handle_gateway_request("gateway_request")

    def do_POST(self) -> None:
        self._handle_gateway_request("gateway_post", read_body=True)

    def do_PUT(self) -> None:
        self._handle_gateway_request("gateway_write", read_body=True)

    def do_PATCH(self) -> None:
        self._handle_gateway_request("gateway_write", read_body=True)

    def do_DELETE(self) -> None:
        self._handle_gateway_request("gateway_request")

    def do_OPTIONS(self) -> None:
        self._handle_gateway_request("gateway_request")

    def _handle_gateway_request(self, event_type: str, read_body: bool = False) -> None:
        body = b""
        payload = ""
        if read_body:
            body = self._read_body_bytes()
            if len(body) > MAX_PROXY_BODY_BYTES:
                self._send_text("request body too large\n", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            payload = body.decode("utf-8", errors="replace")[:4000]

        event = self._record(event_type, payload)
        if event.decision == "redirect_to_decoy":
            self._redirect_to_decoy()
        elif self.backend_url:
            self._proxy_to_backend(body if read_body else None)
        elif self.command == "HEAD":
            self._send_html(REAL_APP_PAGE, include_body=False)
        elif read_body:
            self._send_text("accepted\n")
        else:
            self._send_html(REAL_APP_PAGE)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _record(self, event_type: str, payload: str = "") -> Event:
        forwarded = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        source_ip = forwarded or self.client_address[0]
        event = Event(
            source_ip=source_ip,
            service="gateway",
            event_type=event_type,
            method=self.command,
            path=self.path,
            payload=payload,
            user_agent=self.headers.get("User-Agent", ""),
        )
        event = self.detector.enrich(event)
        self.store.add_event(event)
        return event

    def _read_body_bytes(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_PROXY_BODY_BYTES:
            return self.rfile.read(min(length, MAX_PROXY_BODY_BYTES + 1))
        return self.rfile.read(length)

    def _redirect_to_decoy(self) -> None:
        status = HTTPStatus.TEMPORARY_REDIRECT if self.command not in {"GET", "HEAD"} else HTTPStatus.FOUND
        self.send_response(status)
        self.send_header("Location", f"{self.honeypot_url}{self.path}")
        self.send_header("X-Phantom-Net-Decision", "redirect_to_decoy")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _proxy_to_backend(self, body: bytes | None = None) -> None:
        target = urljoin(self.backend_url.rstrip("/") + "/", self.path.lstrip("/"))
        headers = self._forward_headers()
        headers["X-Phantom-Net-Decision"] = "observe"
        request = Request(target, data=body, headers=headers, method=self.command)
        opener = build_opener(NoRedirectHandler)
        try:
            with opener.open(request, timeout=8) as response:
                data = response.read()
                self._send_backend_response(response.status, response.headers.items(), data)
        except HTTPError as exc:
            data = exc.read()
            self._send_backend_response(exc.code, exc.headers.items(), data)
        except URLError as exc:
            self._send_text(f"backend unavailable: {exc.reason}\n", HTTPStatus.BAD_GATEWAY)

    def _forward_headers(self) -> dict[str, str]:
        headers = {}
        connection_tokens = {
            token.strip().lower()
            for token in self.headers.get("Connection", "").split(",")
            if token.strip()
        }
        blocked = HOP_BY_HOP_HEADERS | connection_tokens | {"host", "content-length"}
        for key, value in self.headers.items():
            if key.lower() not in blocked:
                headers[key] = value

        source_ip = self.headers.get("X-Forwarded-For", "").strip()
        current_ip = self.client_address[0]
        headers["X-Forwarded-For"] = f"{source_ip}, {current_ip}" if source_ip else current_ip
        headers["X-Forwarded-Proto"] = "http"
        headers["X-Forwarded-Host"] = self.headers.get("Host", "")
        headers["Host"] = self._backend_host_header()
        return headers

    def _backend_host_header(self) -> str:
        return self.backend_url.removeprefix("http://").removeprefix("https://").split("/", 1)[0]

    def _send_backend_response(self, status: int, headers: object, body: bytes) -> None:
        self.send_response(status)
        for key, value in headers:
            if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "content-length":
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Phantom-Net-Decision", "observe")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_html(self, body: str, include_body: bool = True) -> None:
        data = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Phantom-Net-Decision", "observe")
        self.end_headers()
        if include_body:
            self.wfile.write(data)

    def _send_text(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Phantom-Net-Decision", "observe")
        self.end_headers()
        self.wfile.write(data)


def make_gateway_server(
    host: str,
    port: int,
    honeypot_port: int,
    store: EventStore,
    detector: BehaviorDetector,
    backend_url: str = "",
) -> ThreadingHTTPServer:
    handler = type(
        "ConfiguredGatewayHandler",
        (GatewayHandler,),
        {
            "store": store,
            "detector": detector,
            "honeypot_url": f"http://{host}:{honeypot_port}",
            "backend_url": backend_url,
        },
    )
    return ThreadingHTTPServer((host, port), handler)
