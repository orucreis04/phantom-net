CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    title TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    analyst_note TEXT NOT NULL DEFAULT '',
    mitre_techniques TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
