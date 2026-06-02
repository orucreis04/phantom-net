from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from time import monotonic
from urllib.request import Request, urlopen

from .config import DATA_DIR
from .models import Event, utc_now


ALERT_PATH = DATA_DIR / "alerts.jsonl"
_lock = threading.Lock()
_last_alert_by_source: dict[str, float] = {}
_runtime_alerts = {"threshold": 90, "cooldown_seconds": 60, "webhook_url": ""}


def configure_alerts(threshold: int, cooldown_seconds: int, webhook_url: str) -> None:
    _runtime_alerts.update(
        {
            "threshold": threshold,
            "cooldown_seconds": cooldown_seconds,
            "webhook_url": webhook_url,
        }
    )


def maybe_alert(event: Event, threshold: int = 90, cooldown_seconds: int = 60) -> None:
    threshold = int(_runtime_alerts.get("threshold", threshold))
    cooldown_seconds = int(_runtime_alerts.get("cooldown_seconds", cooldown_seconds))
    if event.risk_score < threshold:
        return

    now = monotonic()
    last = _last_alert_by_source.get(event.source_ip, 0)
    if now - last < cooldown_seconds:
        return
    _last_alert_by_source[event.source_ip] = now

    alert = {
        "timestamp": utc_now(),
        "source_ip": event.source_ip,
        "service": event.service,
        "event_type": event.event_type,
        "path": event.path,
        "risk_score": event.risk_score,
        "decision": event.decision,
        "tags": event.tags,
    }
    _write_alert(alert)
    _send_webhook(alert)


def _write_alert(alert: dict[str, object], path: Path = ALERT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock, path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(alert) + "\n")


def _send_webhook(alert: dict[str, object]) -> None:
    webhook_url = str(_runtime_alerts.get("webhook_url") or os.getenv("PHANTOM_ALERT_WEBHOOK_URL", "")).strip()
    if not webhook_url:
        return
    payload = json.dumps({"text": "Phantom-Net high risk alert", "alert": alert}).encode("utf-8")
    request = Request(webhook_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        urlopen(request, timeout=4).read()
    except OSError:
        return
