from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Event:
    source_ip: str
    service: str
    event_type: str
    method: str = ""
    path: str = ""
    payload: str = ""
    user_agent: str = ""
    risk_score: int = 0
    decision: str = "observe"
    tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now)
    session_id: str = field(default_factory=lambda: uuid4().hex[:12])

    def as_record(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "service": self.service,
            "event_type": self.event_type,
            "method": self.method,
            "path": self.path,
            "payload": self.payload,
            "user_agent": self.user_agent,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "tags": ",".join(self.tags),
        }
