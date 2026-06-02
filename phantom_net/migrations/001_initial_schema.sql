CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    service TEXT NOT NULL,
    event_type TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    payload TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    decision TEXT NOT NULL,
    tags TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);

CREATE TABLE IF NOT EXISTS ai_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    headline TEXT NOT NULL,
    summary TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    source_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL
);
