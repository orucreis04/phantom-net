from __future__ import annotations

import csv
import io
import json
from typing import Any


EXPORT_FIELDS = (
    "id",
    "timestamp",
    "source_ip",
    "service",
    "event_type",
    "method",
    "path",
    "risk_score",
    "decision",
    "tags",
    "user_agent",
    "payload",
)


def events_to_csv(events: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(events)
    return buffer.getvalue()


def events_to_json(events: list[dict[str, Any]]) -> str:
    return json.dumps({"events": events}, indent=2)
