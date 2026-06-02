from __future__ import annotations

import argparse
import socket
import threading
from time import sleep

from dataclasses import replace

from .alerts import configure_alerts
from .auth import configure_auth
from .ai import configure_ai
from .config import AppConfig, load_config, validate_config
from .dashboard import make_dashboard_server
from .detector import BehaviorDetector
from .gateway import make_gateway_server
from .honeypot import make_honeypot_server
from .rules import rules_from_config
from .siem import configure_siem
from .storage import EventStore
from .tcp_services import make_tcp_server


def _serve(name: str, server) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    thread.start()
    return thread


def _port_is_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((host, port)) != 0


def _required_ports(config: AppConfig) -> list[tuple[str, int]]:
    ports = [
        ("dashboard", config.server.dashboard_port),
        ("honeypot", config.server.honeypot_port),
    ]
    if not config.server.no_gateway:
        ports.append(("gateway", config.server.gateway_port))
    if not config.server.no_tcp_decoys:
        ports.extend((service_name, port) for service_name, port, _ in config.server.tcp_services)
    return ports


def run() -> None:
    parser = argparse.ArgumentParser(description="Phantom-Net defensive deception platform")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--host")
    parser.add_argument("--dashboard-port", type=int)
    parser.add_argument("--gateway-port", type=int)
    parser.add_argument("--honeypot-port", type=int)
    parser.add_argument("--backend-url", help="Optional real backend URL for clean gateway traffic")
    parser.add_argument("--no-gateway", action="store_true", default=None)
    parser.add_argument("--no-tcp-decoys", action="store_true", default=None)
    parser.add_argument("--check-config", action="store_true", help="Validate configuration and exit")
    parser.add_argument("--strict-config", action="store_true", help="Treat configuration warnings as startup errors")
    args = parser.parse_args()

    config = _apply_cli_overrides(load_config(args.config), args)
    if not _report_config_validation(config, args.check_config, args.strict_config):
        raise SystemExit(1)
    if args.check_config:
        return

    configure_auth(
        config.auth.username,
        config.auth.password,
        config.auth.secret,
        config.auth.session_max_age_seconds,
        config.auth.password_hash,
        config.auth.login_window_seconds,
        config.auth.max_login_attempts,
    )
    configure_alerts(config.alerts.threshold, config.alerts.cooldown_seconds, config.alerts.webhook_url)
    configure_ai(config.ai.provider, config.ai.model, config.ai.api_key, config.ai.timeout_seconds)
    configure_siem(
        config.siem.enabled,
        config.siem.formats,
        config.siem.jsonl_path,
        config.siem.cef_path,
        config.siem.syslog_path,
    )

    busy_ports = [
        (name, port) for name, port in _required_ports(config) if not _port_is_available(config.server.host, port)
    ]
    if busy_ports:
        print("Phantom-Net could not start because these ports are already in use:")
        for name, port in busy_ports:
            print(f"- {name}: {config.server.host}:{port}")
        print("\nUse different ports, for example:")
        print("python3 main.py --dashboard-port 8090 --honeypot-port 8091 --gateway-port 8092 --no-tcp-decoys")
        return

    store = EventStore(high_risk_threshold=config.detector.high_risk_threshold)
    detector = BehaviorDetector(
        window_seconds=config.detector.window_seconds,
        burst_window_seconds=config.detector.burst_window_seconds,
        rate_limit_hits=config.detector.rate_limit_hits,
        path_sweep_threshold=config.detector.path_sweep_threshold,
        service_sweep_threshold=config.detector.service_sweep_threshold,
        session_lock_threshold=config.detector.session_lock_threshold,
        session_memory_threshold=config.detector.session_memory_threshold,
        redirect_threshold=config.detector.redirect_threshold,
        rules=rules_from_config(list(config.rules)),
    )
    servers = []

    dashboard = make_dashboard_server(config.server.host, config.server.dashboard_port, store)
    honeypot = make_honeypot_server(
        config.server.host,
        config.server.honeypot_port,
        store,
        detector,
        config.honeypot.response_delay_seconds,
    )
    servers.extend([dashboard, honeypot])
    if not config.server.no_gateway:
        servers.append(
            make_gateway_server(
                config.server.host,
                config.server.gateway_port,
                config.server.honeypot_port,
                store,
                detector,
                config.gateway.backend_url,
            )
        )

    if not config.server.no_tcp_decoys:
        for service_name, port, banner in config.server.tcp_services:
            servers.append(make_tcp_server(config.server.host, port, service_name, banner, store, detector))

    for server in servers:
        _serve(server.__class__.__name__, server)

    print(f"Profile: {config.profile}")
    print(f"Dashboard: http://{config.server.host}:{config.server.dashboard_port}")
    if not config.server.no_gateway:
        print(f"Gateway: http://{config.server.host}:{config.server.gateway_port}")
        if config.gateway.backend_url:
            print(f"Clean traffic backend: {config.gateway.backend_url}")
    print(f"Web honeypot: http://{config.server.host}:{config.server.honeypot_port}")
    if not config.server.no_tcp_decoys:
        print("TCP decoys: " + ", ".join(f"{name}:{port}" for name, port, _ in config.server.tcp_services))
    print("Press Ctrl+C to stop Phantom-Net.")

    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Phantom-Net...")
        for server in servers:
            server.shutdown()


def _apply_cli_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    server = config.server
    gateway = config.gateway
    if args.host is not None:
        server = replace(server, host=args.host)
    if args.dashboard_port is not None:
        server = replace(server, dashboard_port=args.dashboard_port)
    if args.gateway_port is not None:
        server = replace(server, gateway_port=args.gateway_port)
    if args.honeypot_port is not None:
        server = replace(server, honeypot_port=args.honeypot_port)
    if args.no_gateway is not None:
        server = replace(server, no_gateway=args.no_gateway)
    if args.no_tcp_decoys is not None:
        server = replace(server, no_tcp_decoys=args.no_tcp_decoys)
    if args.backend_url is not None:
        gateway = replace(gateway, backend_url=args.backend_url)
    return replace(config, server=server, gateway=gateway)


def _report_config_validation(config: AppConfig, check_only: bool, strict: bool) -> bool:
    errors, warnings = validate_config(config)
    if warnings:
        print("Configuration warnings:")
        for warning in warnings:
            print(f"- {warning}")
    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"- {error}")
        return False
    if strict and warnings:
        print("Strict config mode refused startup because warnings were found.")
        return False
    if check_only:
        print("Configuration OK" if not warnings else "Configuration OK with warnings")
    return True


if __name__ == "__main__":
    run()
