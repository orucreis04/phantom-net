from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "phantom_net.sqlite3"


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    dashboard_port: int = 8080
    gateway_port: int = 8082
    honeypot_port: int = 8081
    no_gateway: bool = False
    no_tcp_decoys: bool = False
    tcp_services: tuple[tuple[str, int, str], ...] = (
        ("ssh", 2222, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"),
        ("mysql", 3306, "5.7.43-phantom-log MySQL Community Server\r\n"),
        ("postgres", 5432, "PostgreSQL 14.9 ready for startup packet\r\n"),
    )


@dataclass(frozen=True)
class AuthConfig:
    username: str = "admin"
    password: str = "phantom-admin"
    password_hash: str = ""
    secret: str = "phantom-net-local-dev-secret"
    session_max_age_seconds: int = 8 * 60 * 60
    login_window_seconds: int = 300
    max_login_attempts: int = 5


@dataclass(frozen=True)
class DetectorConfig:
    window_seconds: int = 90
    burst_window_seconds: int = 10
    rate_limit_hits: int = 6
    path_sweep_threshold: int = 5
    service_sweep_threshold: int = 3
    session_lock_threshold: int = 85
    session_memory_threshold: int = 55
    redirect_threshold: int = 35
    high_risk_threshold: int = 70


@dataclass(frozen=True)
class GatewayConfig:
    backend_url: str = ""


@dataclass(frozen=True)
class HoneypotConfig:
    response_delay_seconds: float = 0.35


@dataclass(frozen=True)
class AlertConfig:
    threshold: int = 90
    cooldown_seconds: int = 60
    webhook_url: str = ""


@dataclass(frozen=True)
class AIConfig:
    provider: str = "local"
    model: str = "gpt-5.2"
    api_key: str = ""
    timeout_seconds: int = 20


@dataclass(frozen=True)
class SIEMConfig:
    enabled: bool = True
    formats: str = "jsonl,cef,syslog"
    jsonl_path: str = "data/siem_events.jsonl"
    cef_path: str = "data/siem_cef.log"
    syslog_path: str = "data/siem_syslog.log"


@dataclass(frozen=True)
class AppConfig:
    profile: str = "dev"
    server: ServerConfig = field(default_factory=ServerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    honeypot: HoneypotConfig = field(default_factory=HoneypotConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    siem: SIEMConfig = field(default_factory=SIEMConfig)
    rules: tuple[dict[str, Any], ...] = ()


DEFAULT_CONFIG = AppConfig()


def validate_config(config: AppConfig) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    ports = [
        config.server.dashboard_port,
        config.server.honeypot_port,
        config.server.gateway_port,
        *(port for _, port, _ in config.server.tcp_services),
    ]
    for port in ports:
        if port < 1 or port > 65535:
            errors.append(f"Invalid TCP port: {port}")

    if config.profile.lower() in {"prod", "production"}:
        if config.auth.password and config.auth.password == DEFAULT_CONFIG.auth.password:
            errors.append("Production profile must not use the default admin password.")
        if not config.auth.password_hash or "..." in config.auth.password_hash:
            errors.append("Production profile must set a real auth.password_hash.")
        if config.auth.secret == DEFAULT_CONFIG.auth.secret or config.auth.secret.startswith("change-this"):
            errors.append("Production profile must set a unique auth.secret or PHANTOM_AUTH_SECRET.")
        if config.server.host in {"127.0.0.1", "localhost"}:
            warnings.append("Production profile is bound to localhost; use 0.0.0.0 behind a firewall/proxy if needed.")

    if not config.gateway.backend_url and not config.server.no_gateway:
        warnings.append("Gateway has no backend_url; clean traffic will receive the local protected-app placeholder.")
    if config.ai.provider == "openai" and not config.ai.api_key:
        warnings.append("AI provider is openai but OPENAI_API_KEY is not set; local fallback will be used.")

    return errors, warnings


def load_config(path: str | Path | None = None) -> AppConfig:
    config = DEFAULT_CONFIG
    config_path = Path(path or "config.yaml")
    if config_path.exists():
        config = _merge_mapping(config, _load_simple_yaml(config_path))
    return _apply_env(config)


def _merge_mapping(config: AppConfig, data: dict[str, Any]) -> AppConfig:
    return replace(
        config,
        profile=str(data.get("profile", config.profile)),
        server=_replace_section(config.server, data.get("server", {})),
        auth=_replace_section(config.auth, data.get("auth", {})),
        detector=_replace_section(config.detector, data.get("detector", {})),
        gateway=_replace_section(config.gateway, data.get("gateway", {})),
        honeypot=_replace_section(config.honeypot, data.get("honeypot", {})),
        alerts=_replace_section(config.alerts, data.get("alerts", {})),
        ai=_replace_section(config.ai, data.get("ai", {})),
        siem=_replace_section(config.siem, data.get("siem", {})),
        rules=tuple(data.get("rules", config.rules) or ()),
    )


def _replace_section(section: Any, values: Any) -> Any:
    if not isinstance(values, dict):
        return section
    allowed = section.__dataclass_fields__.keys()
    clean = {key: value for key, value in values.items() if key in allowed}
    return replace(section, **clean)


def _apply_env(config: AppConfig) -> AppConfig:
    server = replace(
        config.server,
        host=os.getenv("PHANTOM_HOST", config.server.host),
        dashboard_port=_env_int("PHANTOM_DASHBOARD_PORT", config.server.dashboard_port),
        gateway_port=_env_int("PHANTOM_GATEWAY_PORT", config.server.gateway_port),
        honeypot_port=_env_int("PHANTOM_HONEYPOT_PORT", config.server.honeypot_port),
        no_gateway=_env_bool("PHANTOM_NO_GATEWAY", config.server.no_gateway),
        no_tcp_decoys=_env_bool("PHANTOM_NO_TCP_DECOYS", config.server.no_tcp_decoys),
    )
    return replace(
        config,
        profile=os.getenv("PHANTOM_PROFILE", config.profile),
        server=server,
        auth=replace(
            config.auth,
            username=os.getenv("PHANTOM_ADMIN_USER", config.auth.username),
            password=os.getenv("PHANTOM_ADMIN_PASSWORD", config.auth.password),
            password_hash=os.getenv("PHANTOM_ADMIN_PASSWORD_HASH", config.auth.password_hash),
            secret=os.getenv("PHANTOM_AUTH_SECRET", config.auth.secret),
        ),
        gateway=replace(config.gateway, backend_url=os.getenv("PHANTOM_BACKEND_URL", config.gateway.backend_url)),
        alerts=replace(config.alerts, webhook_url=os.getenv("PHANTOM_ALERT_WEBHOOK_URL", config.alerts.webhook_url)),
        ai=replace(
            config.ai,
            provider=os.getenv("PHANTOM_AI_PROVIDER", config.ai.provider),
            model=os.getenv("PHANTOM_OPENAI_MODEL", config.ai.model),
            api_key=os.getenv("OPENAI_API_KEY", config.ai.api_key),
        ),
        siem=replace(
            config.siem,
            enabled=_env_bool("PHANTOM_SIEM_ENABLED", config.siem.enabled),
            formats=os.getenv("PHANTOM_SIEM_FORMATS", config.siem.formats),
            jsonl_path=os.getenv("PHANTOM_SIEM_JSONL_PATH", config.siem.jsonl_path),
            cef_path=os.getenv("PHANTOM_SIEM_CEF_PATH", config.siem.cef_path),
            syslog_path=os.getenv("PHANTOM_SIEM_SYSLOG_PATH", config.siem.syslog_path),
        ),
    )


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_simple_yaml(path: Path) -> dict[str, Any]:
    root: dict[str, Any] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        line = _clean_line(lines[index])
        index += 1
        if not line:
            continue
        indent = _indent(line)
        if indent != 0:
            continue
        key, sep, value = line.strip().partition(":")
        if not sep:
            continue
        if value.strip():
            root[key] = _parse_scalar(value.strip())
            continue
        block, index = _parse_block(lines, index, indent + 2)
        root[key] = block
    return root


def _parse_block(lines: list[str], index: int, expected_indent: int) -> tuple[Any, int]:
    mapping: dict[str, Any] = {}
    sequence: list[Any] = []
    mode = "mapping"
    while index < len(lines):
        line = _clean_line(lines[index])
        if not line:
            index += 1
            continue
        indent = _indent(line)
        if indent < expected_indent:
            break
        stripped = line.strip()
        if stripped.startswith("- "):
            mode = "sequence"
            item_text = stripped[2:]
            item: dict[str, Any] = {}
            if item_text:
                key, sep, value = item_text.partition(":")
                if sep:
                    item[key] = _parse_scalar(value.strip())
            index += 1
            while index < len(lines):
                child = _clean_line(lines[index])
                if not child:
                    index += 1
                    continue
                child_indent = _indent(child)
                if child_indent <= indent:
                    break
                key, sep, value = child.strip().partition(":")
                if sep:
                    item[key] = _parse_scalar(value.strip())
                index += 1
            sequence.append(item)
            continue
        key, sep, value = stripped.partition(":")
        index += 1
        if sep:
            mapping[key] = _parse_scalar(value.strip()) if value.strip() else {}
    return (sequence if mode == "sequence" else mapping), index


def _clean_line(raw_line: str) -> str:
    return raw_line.split("#", 1)[0].rstrip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_scalar(value: str) -> Any:
    if value in {'""', "''"}:
        return ""
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value
