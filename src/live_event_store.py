"""Persistent SQLite storage for AI-IDS live monitoring.

The live monitor and the future Streamlit dashboard share this database.  Each
operation opens its own short-lived SQLite connection so capture/analysis
threads and dashboard readers can safely access the store concurrently.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVENT_DB = PROJECT_ROOT / "data" / "live" / "live_events.db"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_default(value: Any) -> str:
    return str(value)


def _text(value: Any, default: str | None = None) -> str | None:
    if value is None:
        return default
    return str(value)


class LiveEventStore:
    """SQLite-backed event store for live capture sessions, windows and alerts."""

    def __init__(self, db_path: Path | str = DEFAULT_EVENT_DB) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.db_path,
            timeout=10.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS live_sessions (
                    session_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    interface TEXT NOT NULL,
                    window_seconds REAL NOT NULL,
                    bpf_filter TEXT,
                    status TEXT NOT NULL DEFAULT 'RUNNING'
                );

                CREATE TABLE IF NOT EXISTS live_windows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    captured_at TEXT,
                    analyzed_at TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    pcap_path TEXT,
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    flow_count INTEGER NOT NULL DEFAULT 0,
                    final_decision TEXT,
                    severity TEXT,
                    attack_type TEXT,
                    detection_source TEXT,
                    ml_attack_flows INTEGER NOT NULL DEFAULT 0,
                    behavioral_alerts INTEGER NOT NULL DEFAULT 0,
                    web_alerts INTEGER NOT NULL DEFAULT 0,
                    reason TEXT,
                    report_path TEXT,
                    report_json TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES live_sessions(session_id)
                        ON DELETE CASCADE,
                    UNIQUE(session_id, sequence)
                );

                CREATE TABLE IF NOT EXISTS live_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    window_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    attack_type TEXT,
                    severity TEXT,
                    detection_engine TEXT,
                    source_ip TEXT,
                    target_ip TEXT,
                    source_port TEXT,
                    target_port TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    reason TEXT,
                    notification_emitted INTEGER NOT NULL DEFAULT 0,
                    alert_json TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES live_sessions(session_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY(window_id) REFERENCES live_windows(id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_live_windows_analyzed_at
                    ON live_windows(analyzed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_live_windows_decision
                    ON live_windows(final_decision);
                CREATE INDEX IF NOT EXISTS idx_live_alerts_created_at
                    ON live_alerts(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_live_alerts_severity
                    ON live_alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_live_alerts_attack_type
                    ON live_alerts(attack_type);
                """
            )

    def start_session(
        self,
        session_id: str,
        interface: str,
        window_seconds: float,
        bpf_filter: str | None,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT OR REPLACE INTO live_sessions (
                    session_id, started_at, ended_at, interface,
                    window_seconds, bpf_filter, status
                ) VALUES (?, ?, NULL, ?, ?, ?, 'RUNNING')
                """,
                (
                    session_id,
                    _utc_now(),
                    interface,
                    float(window_seconds),
                    bpf_filter,
                ),
            )
            connection.commit()

    def finish_session(self, session_id: str, status: str = "COMPLETED") -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE live_sessions
                SET ended_at = ?, status = ?
                WHERE session_id = ?
                """,
                (_utc_now(), status, session_id),
            )

    def record_window(
        self,
        *,
        session_id: str,
        sequence: int,
        interface: str,
        pcap_path: Path | str,
        packet_count: int,
        report: dict[str, Any],
        captured_at: str | None = None,
        notified_alerts: Iterable[dict[str, Any]] = (),
    ) -> int:
        """Atomically persist one analyzed window and all of its alerts."""
        alerts = report.get("alerts", [])
        if not isinstance(alerts, list):
            alerts = []

        notified_ids = {id(alert) for alert in notified_alerts}
        pcap = Path(pcap_path)
        report_path = (
            PROJECT_ROOT
            / "data"
            / "processed"
            / "security_reports"
            / f"{pcap.stem}_security_report.json"
        )

        report_json = json.dumps(
            report,
            ensure_ascii=False,
            default=_json_default,
            separators=(",", ":"),
        )

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT INTO live_windows (
                    session_id, sequence, captured_at, analyzed_at, interface,
                    pcap_path, packet_count, flow_count, final_decision,
                    severity, attack_type, detection_source, ml_attack_flows,
                    behavioral_alerts, web_alerts, reason, report_path,
                    report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, sequence) DO UPDATE SET
                    captured_at = excluded.captured_at,
                    analyzed_at = excluded.analyzed_at,
                    interface = excluded.interface,
                    pcap_path = excluded.pcap_path,
                    packet_count = excluded.packet_count,
                    flow_count = excluded.flow_count,
                    final_decision = excluded.final_decision,
                    severity = excluded.severity,
                    attack_type = excluded.attack_type,
                    detection_source = excluded.detection_source,
                    ml_attack_flows = excluded.ml_attack_flows,
                    behavioral_alerts = excluded.behavioral_alerts,
                    web_alerts = excluded.web_alerts,
                    reason = excluded.reason,
                    report_path = excluded.report_path,
                    report_json = excluded.report_json
                RETURNING id
                """,
                (
                    session_id,
                    int(sequence),
                    captured_at,
                    _utc_now(),
                    interface,
                    str(pcap),
                    int(packet_count),
                    int(report.get("total_flows", 0) or 0),
                    _text(report.get("final_decision"), "UNKNOWN"),
                    _text(report.get("severity"), "UNKNOWN"),
                    _text(report.get("attack_type"), "Unknown"),
                    _text(report.get("detection_source"), "Unknown"),
                    int(report.get("ml_attack_flows", 0) or 0),
                    int(report.get("behavioral_alerts", 0) or 0),
                    int(report.get("web_alerts", 0) or 0),
                    _text(report.get("reason"), ""),
                    str(report_path),
                    report_json,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                raise RuntimeError("Failed to persist live window")
            window_id = int(row[0])

            # A repeated write of the same session/window replaces its alerts,
            # keeping persistence idempotent during retries.
            connection.execute(
                "DELETE FROM live_alerts WHERE window_id = ?",
                (window_id,),
            )

            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                connection.execute(
                    """
                    INSERT INTO live_alerts (
                        session_id, window_id, created_at, attack_type, severity,
                        detection_engine, source_ip, target_ip, source_port,
                        target_port, first_seen, last_seen, reason,
                        notification_emitted, alert_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        window_id,
                        _utc_now(),
                        _text(alert.get("attack_type"), "Unknown"),
                        _text(alert.get("severity"), "Unknown"),
                        _text(alert.get("detection_engine"), "Unknown"),
                        _text(alert.get("source_ip"), "Unknown"),
                        _text(alert.get("target_ip"), "Unknown"),
                        _text(alert.get("source_port")),
                        _text(alert.get("target_port")),
                        _text(alert.get("first_seen")),
                        _text(alert.get("last_seen")),
                        _text(alert.get("reason"), ""),
                        1 if id(alert) in notified_ids else 0,
                        json.dumps(
                            alert,
                            ensure_ascii=False,
                            default=_json_default,
                            separators=(",", ":"),
                        ),
                    ),
                )

            connection.commit()
            return window_id

    def recent_windows(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM live_windows
                ORDER BY analyzed_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 5000))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM live_alerts
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def overview(self) -> dict[str, int]:
        with self._connect() as connection:
            window_row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_windows,
                    COALESCE(SUM(packet_count), 0) AS total_packets,
                    COALESCE(SUM(flow_count), 0) AS total_flows,
                    COALESCE(SUM(CASE WHEN final_decision = 'ATTACK' THEN 1 ELSE 0 END), 0)
                        AS attack_windows
                FROM live_windows
                """
            ).fetchone()
            alert_row = connection.execute(
                "SELECT COUNT(*) AS total_alerts FROM live_alerts"
            ).fetchone()

        return {
            "total_windows": int(window_row["total_windows"]),
            "total_packets": int(window_row["total_packets"]),
            "total_flows": int(window_row["total_flows"]),
            "attack_windows": int(window_row["attack_windows"]),
            "total_alerts": int(alert_row["total_alerts"]),
        }
