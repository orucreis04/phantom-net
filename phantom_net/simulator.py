from __future__ import annotations

import argparse
import http.client
import socket
from urllib.parse import urlencode


DEFAULT_PATHS = (
    "/",
    "/admin",
    "/admin/users",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/files",
    "/api/db/tables",
    "/api/db/query?q=select%20*%20from%20api_keys%20limit%205",
    "/backup",
    "/backup/daily-prod-2026-05-23.tar.gz",
    "/export/customer_export_2026_05.csv",
    "/api/users",
)


def hit_http(host: str, port: int, path: str) -> None:
    conn = http.client.HTTPConnection(host, port, timeout=3)
    conn.request("GET", path, headers={"User-Agent": "phantom-net-simulator/0.1"})
    response = conn.getresponse()
    response.read()
    conn.close()
    print(f"GET {path} -> {response.status}")


def post_login(host: str, port: int, username: str, password: str) -> None:
    body = urlencode({"username": username, "password": password})
    conn = http.client.HTTPConnection(host, port, timeout=3)
    conn.request(
        "POST",
        "/login",
        body=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "phantom-net-simulator/0.1",
        },
    )
    response = conn.getresponse()
    response.read()
    conn.close()
    print(f"POST /login {username}:{password} -> {response.status}")


def probe_tcp(host: str, port: int) -> None:
    with socket.create_connection((host, port), timeout=3) as sock:
        banner = sock.recv(256)
        sock.sendall(b"admin password test\r\n")
        reply = sock.recv(256)
    print(f"TCP {port} banner={banner.decode(errors='replace').strip()} reply={reply.decode(errors='replace').strip()}")


def run() -> None:
    parser = argparse.ArgumentParser(description="Generate local Phantom-Net demo traffic")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--honeypot-port", type=int, default=8081)
    parser.add_argument("--skip-tcp", action="store_true")
    args = parser.parse_args()

    for path in DEFAULT_PATHS:
        hit_http(args.host, args.honeypot_port, path)

    for password in ("admin", "123456", "password", "Spring2026!"):
        post_login(args.host, args.honeypot_port, "admin", password)

    if not args.skip_tcp:
        for port in (2222, 3306, 5432):
            probe_tcp(args.host, port)


if __name__ == "__main__":
    run()
