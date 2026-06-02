from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from time import monotonic
from urllib.parse import urlsplit

from .models import Event
from .rules import DEFAULT_RULES, Rule, RuleEngine


SUSPICIOUS_PATH_HINTS = (
    "admin",
    "wp-login",
    "phpmyadmin",
    ".env",
    "backup",
    "config",
    "shell",
    "cmd",
)

BRUTE_FORCE_HINTS = ("login", "password", "passwd", "username", "admin")
TRUSTED_FRONT_DOOR_SERVICES = {"web", "gateway"}


@dataclass
class SessionState:
    first_seen: float
    last_seen: float
    event_count: int = 0
    max_risk: int = 0
    decoy_locked: bool = False
    recent_hits: deque[float] = field(default_factory=deque)
    recent_paths: deque[tuple[float, str]] = field(default_factory=deque)
    recent_services: deque[tuple[float, str]] = field(default_factory=deque)


@dataclass
class BehaviorDetector:
    window_seconds: int = 90
    burst_window_seconds: int = 10
    rate_limit_hits: int = 6
    path_sweep_threshold: int = 5
    service_sweep_threshold: int = 3
    session_lock_threshold: int = 85
    session_memory_threshold: int = 55
    redirect_threshold: int = 35
    rules: list[Rule] | tuple[Rule, ...] = DEFAULT_RULES
    _sessions: dict[str, SessionState] = field(default_factory=dict)
    _rule_engine: RuleEngine = field(init=False)

    def __post_init__(self) -> None:
        self._rule_engine = RuleEngine(self.rules)

    def enrich(self, event: Event) -> Event:
        now = monotonic()
        session = self._session_for(event.source_ip, now)
        session.last_seen = now
        session.event_count += 1

        normalized_path = self._normalize_path(event.path)
        session.recent_hits.append(now)
        if normalized_path:
            session.recent_paths.append((now, normalized_path))
        session.recent_services.append((now, event.service))

        self._trim_times(session.recent_hits, now, self.window_seconds)
        self._trim_pairs(session.recent_paths, now, self.window_seconds)
        self._trim_pairs(session.recent_services, now, self.window_seconds)

        haystack = f"{event.path} {event.payload}".lower()
        recent_burst = self._count_recent(session.recent_hits, now, self.burst_window_seconds)
        unique_paths = {path for _, path in session.recent_paths}
        unique_probe_services = {
            service
            for _, service in session.recent_services
            if service not in TRUSTED_FRONT_DOOR_SERVICES
        }
        facts = {
            "base_score": 5,
            "service_trusted": event.service in TRUSTED_FRONT_DOOR_SERVICES,
            "event_type": event.event_type,
            "payload": event.payload.lower(),
            "haystack": haystack,
            "recent_burst": recent_burst,
            "recent_hits": len(session.recent_hits),
            "unique_paths": len(unique_paths),
            "unique_probe_services": len(unique_probe_services),
            "session_max_risk": session.max_risk,
            "decoy_locked": session.decoy_locked,
            "rate_limit_hits": self.rate_limit_hits,
            "path_sweep_threshold": self.path_sweep_threshold,
            "service_sweep_threshold": self.service_sweep_threshold,
            "session_memory_threshold": self.session_memory_threshold,
            "suspicious_path_hints": SUSPICIOUS_PATH_HINTS,
            "brute_force_hints": BRUTE_FORCE_HINTS,
        }
        score, tags = self._rule_engine.evaluate(facts)

        event.risk_score = min(score, 100)
        event.tags = tags
        event.decision = "redirect_to_decoy" if event.risk_score >= self.redirect_threshold else "observe"
        session.max_risk = max(session.max_risk, event.risk_score)
        if event.risk_score >= self.session_lock_threshold:
            session.decoy_locked = True
        return event

    def _session_for(self, source_ip: str, now: float) -> SessionState:
        session = self._sessions.get(source_ip)
        if session is None:
            session = SessionState(first_seen=now, last_seen=now)
            self._sessions[source_ip] = session
        return session

    def _normalize_path(self, path: str) -> str:
        if not path:
            return ""
        parsed = urlsplit(path)
        normalized = parsed.path.rstrip("/") or "/"
        return normalized.lower()

    def _trim_times(self, values: deque[float], now: float, window: int) -> None:
        while values and now - values[0] > window:
            values.popleft()

    def _trim_pairs(self, values: deque[tuple[float, str]], now: float, window: int) -> None:
        while values and now - values[0][0] > window:
            values.popleft()

    def _count_recent(self, values: deque[float], now: float, window: int) -> int:
        return sum(1 for value in values if now - value <= window)
