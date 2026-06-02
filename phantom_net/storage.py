from __future__ import annotations

import sqlite3
import threading
import json
from pathlib import Path
from typing import Any

from .alerts import maybe_alert
from .config import DB_PATH
from .migrations import applied_migrations, run_migrations
from .mitre import enrich_event, techniques_for_tags
from .models import Event
from .redaction import redact_payload
from .siem import export_siem_event


class EventStore:
    def __init__(self, db_path: Path = DB_PATH, high_risk_threshold: int = 70) -> None:
        self.db_path = db_path
        self.high_risk_threshold = high_risk_threshold
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            run_migrations(conn)

    def add_event(self, event: Event) -> None:
        record = event.as_record()
        record["payload"] = redact_payload(record["payload"])
        fields = ", ".join(record.keys())
        placeholders = ", ".join("?" for _ in record)
        with self._lock, self._connect() as conn:
            conn.execute(
                f"INSERT INTO events ({fields}) VALUES ({placeholders})",
                tuple(record.values()),
            )
        export_siem_event(enrich_event(record))
        maybe_alert(event)

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [enrich_event(dict(row)) for row in rows]

    def events(
        self,
        limit: int = 100,
        source_ip: str | None = None,
        decision: str | None = None,
        min_risk: int | None = None,
    ) -> list[dict[str, Any]]:
        where = []
        values: list[Any] = []
        if source_ip:
            where.append("source_ip = ?")
            values.append(source_ip)
        if decision:
            where.append("decision = ?")
            values.append(decision)
        if min_risk is not None:
            where.append("risk_score >= ?")
            values.append(min_risk)

        clause = f"WHERE {' AND '.join(where)}" if where else ""
        values.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM events {clause} ORDER BY id DESC LIMIT ?",
                tuple(values),
            ).fetchall()
        return [enrich_event(dict(row)) for row in rows]

    def source_detail(self, source_ip: str, limit: int = 100) -> dict[str, Any]:
        with self._connect() as conn:
            summary = conn.execute(
                """
                SELECT
                    source_ip,
                    COUNT(*) AS total_events,
                    MAX(risk_score) AS max_risk,
                    SUM(CASE WHEN risk_score >= ? THEN 1 ELSE 0 END) AS high_risk_events,
                    SUM(CASE WHEN decision = 'redirect_to_decoy' THEN 1 ELSE 0 END) AS redirected_events,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen
                FROM events
                WHERE source_ip = ?
                GROUP BY source_ip
                """,
                (self.high_risk_threshold, source_ip),
            ).fetchone()
            service_rows = conn.execute(
                """
                SELECT service, COUNT(*) AS count
                FROM events
                WHERE source_ip = ?
                GROUP BY service
                ORDER BY count DESC
                """,
                (source_ip,),
            ).fetchall()
            tag_rows = conn.execute(
                "SELECT tags FROM events WHERE source_ip = ? AND tags != ''",
                (source_ip,),
            ).fetchall()

        tag_counts: dict[str, int] = {}
        for row in tag_rows:
            for tag in row["tags"].split(","):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "summary": dict(summary) if summary else None,
            "services": [dict(row) for row in service_rows],
            "tags": [
                {"tag": tag, "count": count}
                for tag, count in sorted(tag_counts.items(), key=lambda item: item[1], reverse=True)
            ],
            "events": self.events(limit=limit, source_ip=source_ip),
        }

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            attackers = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM events"
            ).fetchone()[0]
            high_risk = conn.execute(
                "SELECT COUNT(*) FROM events WHERE risk_score >= ?",
                (self.high_risk_threshold,),
            ).fetchone()[0]
            redirected = conn.execute(
                "SELECT COUNT(*) FROM events WHERE decision = 'redirect_to_decoy'"
            ).fetchone()[0]
            top_ips = conn.execute(
                """
                SELECT source_ip, COUNT(*) AS count, MAX(risk_score) AS max_risk
                FROM events
                GROUP BY source_ip
                ORDER BY count DESC, max_risk DESC
                LIMIT 8
                """
            ).fetchall()
            tag_rows = conn.execute("SELECT tags FROM events WHERE tags != ''").fetchall()
        tag_counts: dict[str, int] = {}
        for row in tag_rows:
            for tag in row["tags"].split(","):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        top_tags = sorted(tag_counts.items(), key=lambda item: item[1], reverse=True)[:8]
        return {
            "total_events": total,
            "unique_sources": attackers,
            "high_risk_events": high_risk,
            "redirected_sessions": redirected,
            "top_ips": [dict(row) for row in top_ips],
            "top_tags": [{"tags": tag, "count": count} for tag, count in top_tags],
        }

    def attack_summary(self, period: str = "daily", limit: int = 14) -> dict[str, Any]:
        bucket_expression = "substr(timestamp, 1, 10)"
        if period == "weekly":
            bucket_expression = "strftime('%Y-W%W', timestamp)"
        elif period != "daily":
            period = "daily"

        with self._connect() as conn:
            buckets = conn.execute(
                f"""
                SELECT
                    {bucket_expression} AS bucket,
                    COUNT(*) AS total_events,
                    COUNT(DISTINCT source_ip) AS unique_sources,
                    SUM(CASE WHEN risk_score >= ? THEN 1 ELSE 0 END) AS high_risk_events,
                    SUM(CASE WHEN decision = 'redirect_to_decoy' THEN 1 ELSE 0 END) AS redirected_events,
                    MAX(risk_score) AS max_risk
                FROM events
                GROUP BY bucket
                ORDER BY bucket DESC
                LIMIT ?
                """,
                (self.high_risk_threshold, limit),
            ).fetchall()
            risky_ips = conn.execute(
                """
                SELECT
                    source_ip,
                    COUNT(*) AS total_events,
                    MAX(risk_score) AS max_risk,
                    SUM(CASE WHEN risk_score >= ? THEN 1 ELSE 0 END) AS high_risk_events,
                    SUM(CASE WHEN decision = 'redirect_to_decoy' THEN 1 ELSE 0 END) AS redirected_events,
                    MIN(timestamp) AS first_seen,
                    MAX(timestamp) AS last_seen
                FROM events
                GROUP BY source_ip
                ORDER BY max_risk DESC, high_risk_events DESC, total_events DESC
                LIMIT 10
                """,
                (self.high_risk_threshold,),
            ).fetchall()
            tag_rows = conn.execute("SELECT tags FROM events WHERE tags != ''").fetchall()
            event_type_rows = conn.execute(
                """
                SELECT event_type, COUNT(*) AS count, MAX(risk_score) AS max_risk
                FROM events
                GROUP BY event_type
                ORDER BY count DESC, max_risk DESC
                LIMIT 10
                """
            ).fetchall()

        tag_counts: dict[str, int] = {}
        for row in tag_rows:
            for tag in row["tags"].split(","):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        attack_types = [
            {"type": tag, "count": count}
            for tag, count in sorted(tag_counts.items(), key=lambda item: item[1], reverse=True)[:10]
        ]
        mitre_counter: dict[str, dict[str, Any]] = {}
        for tag, count in tag_counts.items():
            for technique in techniques_for_tags([tag]):
                current = mitre_counter.setdefault(technique["id"], {**technique, "count": 0})
                current["count"] += count

        return {
            "period": period,
            "buckets": [dict(row) for row in reversed(buckets)],
            "risky_ips": [dict(row) for row in risky_ips],
            "attack_types": attack_types,
            "mitre_techniques": sorted(mitre_counter.values(), key=lambda item: item["count"], reverse=True),
            "event_types": [dict(row) for row in event_type_rows],
        }

    def save_ai_report(self, summary: dict[str, Any], decoy_data: dict[str, Any]) -> dict[str, Any]:
        payload = {"summary": summary, "decoy_data": decoy_data}
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO ai_reports (timestamp, severity, headline, summary, payload)
                VALUES (datetime('now'), ?, ?, ?, ?)
                """,
                (
                    summary.get("severity", "unknown"),
                    summary.get("headline", ""),
                    summary.get("summary", ""),
                    json.dumps(payload),
                ),
            )
            report_id = cursor.lastrowid
        return {"id": report_id, **payload}

    def ai_reports(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ai_reports ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        reports = []
        for row in rows:
            record = dict(row)
            record["payload"] = json.loads(record["payload"])
            reports.append(record)
        return reports

    def add_admin_audit(self, source_ip: str, action: str, status: str, detail: str = "") -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO admin_audit (source_ip, action, status, detail)
                VALUES (?, ?, ?, ?)
                """,
                (source_ip, action, status, detail),
            )

    def admin_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM admin_audit ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_incident(
        self,
        source_ip: str,
        title: str = "",
        severity: str = "high",
        analyst_note: str = "",
    ) -> dict[str, Any]:
        detail = self.source_detail(source_ip, limit=50)
        tags = [row["tag"] for row in detail["tags"]]
        techniques = techniques_for_tags(tags)
        if not title:
            title = f"Suspicious activity from {source_ip}"
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO incidents (title, source_ip, severity, analyst_note, mitre_techniques)
                VALUES (?, ?, ?, ?, ?)
                """,
                (title, source_ip, severity, analyst_note, json.dumps(techniques)),
            )
            incident_id = cursor.lastrowid
        return self.get_incident(int(incident_id))

    def update_incident(
        self,
        incident_id: int,
        status: str | None = None,
        severity: str | None = None,
        analyst_note: str | None = None,
    ) -> dict[str, Any] | None:
        fields = ["updated_at = datetime('now')"]
        values: list[Any] = []
        if status:
            fields.append("status = ?")
            values.append(status)
        if severity:
            fields.append("severity = ?")
            values.append(severity)
        if analyst_note is not None:
            fields.append("analyst_note = ?")
            values.append(analyst_note)
        values.append(incident_id)
        with self._lock, self._connect() as conn:
            conn.execute(f"UPDATE incidents SET {', '.join(fields)} WHERE id = ?", tuple(values))
        return self.get_incident(incident_id)

    def get_incident(self, incident_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._incident_record(row) if row else None

    def incidents(self, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        clause = "WHERE status = ?" if status else ""
        values: tuple[Any, ...] = (status, limit) if status else (limit,)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM incidents {clause} ORDER BY id DESC LIMIT ?",
                values,
            ).fetchall()
        return [self._incident_record(row) for row in rows]

    def migration_versions(self) -> list[str]:
        with self._connect() as conn:
            return applied_migrations(conn)

    def health(self) -> dict[str, Any]:
        try:
            with self._connect() as conn:
                conn.execute("SELECT 1").fetchone()
                event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            return {
                "ok": True,
                "database": str(self.db_path),
                "event_count": event_count,
                "migrations": self.migration_versions(),
            }
        except sqlite3.Error as exc:
            return {
                "ok": False,
                "database": str(self.db_path),
                "error": str(exc),
            }

    def _incident_record(self, row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        try:
            record["mitre_techniques"] = json.loads(record["mitre_techniques"])
        except json.JSONDecodeError:
            record["mitre_techniques"] = []
        return record
