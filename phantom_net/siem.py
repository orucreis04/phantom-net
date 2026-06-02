from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT


@dataclass(frozen=True)
class SIEMState:
    enabled: bool
    formats: tuple[str, ...]
    jsonl_path: Path
    cef_path: Path
    syslog_path: Path


_lock = threading.Lock()
_state = SIEMState(
    enabled=True,
    formats=("jsonl", "cef", "syslog"),
    jsonl_path=PROJECT_ROOT / "data" / "siem_events.jsonl",
    cef_path=PROJECT_ROOT / "data" / "siem_cef.log",
    syslog_path=PROJECT_ROOT / "data" / "siem_syslog.log",
)


def configure_siem(
    enabled: bool,
    formats: str,
    jsonl_path: str,
    cef_path: str,
    syslog_path: str,
) -> None:
    global _state
    parsed_formats = tuple(
        item.strip().lower() for item in formats.split(",") if item.strip().lower() in {"jsonl", "cef", "syslog"}
    )
    if not parsed_formats:
        parsed_formats = ("jsonl",)
    _state = SIEMState(
        enabled=enabled,
        formats=parsed_formats,
        jsonl_path=_resolve_path(jsonl_path),
        cef_path=_resolve_path(cef_path),
        syslog_path=_resolve_path(syslog_path),
    )


def siem_status() -> dict[str, Any]:
    return {
        "enabled": _state.enabled,
        "formats": list(_state.formats),
        "targets": {
            "jsonl": str(_state.jsonl_path),
            "cef": str(_state.cef_path),
            "syslog": str(_state.syslog_path),
        },
    }


def export_siem_event(event: dict[str, Any]) -> None:
    if not _state.enabled:
        return

    with _lock:
        if "jsonl" in _state.formats:
            _append_line(_state.jsonl_path, _jsonl_event(event))
        if "cef" in _state.formats:
            _append_line(_state.cef_path, _cef_event(event))
        if "syslog" in _state.formats:
            _append_line(_state.syslog_path, _syslog_event(event))


def _jsonl_event(event: dict[str, Any]) -> str:
    payload = {
        "vendor": "Phantom-Net",
        "product": "Deception Defense",
        "timestamp": event.get("timestamp", ""),
        "session_id": event.get("session_id", ""),
        "source_ip": event.get("source_ip", ""),
        "service": event.get("service", ""),
        "event_type": event.get("event_type", ""),
        "method": event.get("method", ""),
        "path": event.get("path", ""),
        "payload": event.get("payload", ""),
        "user_agent": event.get("user_agent", ""),
        "risk_score": int(event.get("risk_score") or 0),
        "decision": event.get("decision", ""),
        "tags": _split_tags(event.get("tags", "")),
        "mitre_techniques": event.get("mitre_techniques", []),
    }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _cef_event(event: dict[str, Any]) -> str:
    risk = int(event.get("risk_score") or 0)
    severity = max(1, min(10, risk // 10))
    tags = ",".join(_split_tags(event.get("tags", "")))
    mitre = ",".join(item.get("id", "") for item in event.get("mitre_techniques", []) if item.get("id"))
    name = f"{event.get('event_type', 'event')} {event.get('decision', 'observe')}"
    fields = {
        "src": event.get("source_ip", ""),
        "suser": event.get("session_id", ""),
        "requestMethod": event.get("method", ""),
        "request": event.get("path", ""),
        "cs1Label": "service",
        "cs1": event.get("service", ""),
        "cs2Label": "tags",
        "cs2": tags,
        "cs3Label": "mitre",
        "cs3": mitre,
        "flexNumber1Label": "risk_score",
        "flexNumber1": str(risk),
    }
    extension = " ".join(f"{key}={_cef_escape(str(value))}" for key, value in fields.items() if value)
    return f"CEF:0|Phantom-Net|Deception Defense|0.1|{_cef_escape(str(event.get('event_type', 'event')))}|{_cef_escape(name)}|{severity}|{extension}"


def _syslog_event(event: dict[str, Any]) -> str:
    timestamp = str(event.get("timestamp", ""))
    risk = int(event.get("risk_score") or 0)
    message = {
        "source_ip": event.get("source_ip", ""),
        "service": event.get("service", ""),
        "event_type": event.get("event_type", ""),
        "risk_score": risk,
        "decision": event.get("decision", ""),
        "tags": _split_tags(event.get("tags", "")),
    }
    return f"<134>{timestamp} phantom-net phantom-net: {json.dumps(message, ensure_ascii=True, separators=(',', ':'))}"


def _append_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _split_tags(tags: Any) -> list[str]:
    if isinstance(tags, list):
        return [str(tag) for tag in tags if str(tag)]
    return [tag for tag in str(tags or "").split(",") if tag]


def _cef_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")
