from __future__ import annotations

import json
import hashlib
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings

DB_PATH = Path(settings.data_dir / "alerts.sqlite3")
LOCK = threading.Lock()
logger = logging.getLogger(__name__)

MITRE_BY_RULE_NAME = {
    "port scan": ("T1046", "Network Service Discovery"),
    "syn flood indicators": ("T1498.001", "Direct Network Flood"),
    "icmp flood indicators": ("T1498.001", "Direct Network Flood"),
    "dns anomalies": ("T1071.004", "DNS"),
    "arp spoofing indicators": ("T1557.002", "ARP Cache Poisoning"),
    "suspicious outbound connections": ("T1571", "Non-Standard Port"),
}
MITRE_BY_RULE_ID = {
    "port-scan": ("T1021", "Remote Services"),
    "ssh-monitor": ("T1021.004", "SSH"),
    "rdp-monitor": ("T1021.001", "Remote Desktop Protocol"),
    "dns-anomaly": ("T1071.004", "DNS"),
    "dns-repetition": ("T1071.004", "DNS"),
    "service-discovery": ("T1046", "Network Service Discovery"),
    "icmp-flood": ("T1498.001", "Direct Network Flood"),
}


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def _ensure_alerts_schema(db: sqlite3.Connection) -> None:
    existing_columns = {
        row[1] for row in db.execute("PRAGMA table_info(alerts)").fetchall()
    }

    if not existing_columns:
        db.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                detection TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                status TEXT NOT NULL DEFAULT 'New',
                assigned_analyst TEXT,
                details TEXT NOT NULL,
                evidence_json TEXT DEFAULT '{}',
                source_file TEXT,
                rule_id TEXT,
                alert_type TEXT DEFAULT 'pcap'
            )
            """
        )
        return

    for column_name, column_sql in {
        "detection": "TEXT NOT NULL DEFAULT 'unknown'",
        "status": "TEXT NOT NULL DEFAULT 'New'",
        "assigned_analyst": "TEXT",
        "evidence_json": "TEXT DEFAULT '{}'",
        "rule_id": "TEXT",
        "alert_type": "TEXT DEFAULT 'pcap'",
    }.items():
        if column_name not in existing_columns:
            db.execute(f"ALTER TABLE alerts ADD COLUMN {column_name} {column_sql}")


def _repair_duplicate_pcap_records(db: sqlite3.Connection) -> None:
    migration_id = "2026-11-pcap-raw-sha256-dedup-cleanup"
    if db.execute("SELECT 1 FROM schema_migrations WHERE migration_id = ?", (migration_id,)).fetchone():
        return

    db.execute("DROP INDEX IF EXISTS idx_pcap_analysis_sha256")
    rows = db.execute(
        "SELECT id, file_name, sha256, stored_path FROM pcap_analysis ORDER BY id"
    ).fetchall()
    grouped: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        digest = row["sha256"]
        stored_path = row["stored_path"]
        if stored_path and Path(stored_path).is_file():
            try:
                digest = hashlib.sha256(Path(stored_path).read_bytes()).hexdigest()
                if digest != row["sha256"]:
                    db.execute("UPDATE pcap_analysis SET sha256 = ? WHERE id = ?", (digest, row["id"]))
            except OSError:
                logger.warning("Could not verify stored PCAP %s during deduplication migration", row["id"])
        if digest:
            grouped.setdefault(digest, []).append(row)

    removed_analyses = 0
    removed_flows = 0
    for digest, analyses in grouped.items():
        if len(analyses) < 2:
            continue
        oldest = analyses[0]
        old_digests = {str(item["sha256"]) for item in analyses if item["sha256"]}
        capture_prefixes = [f"pcap:{value}:%" for value in old_digests | {digest}]
        flow_ids: list[tuple[int, str | None]] = []
        for prefix in capture_prefixes:
            flow_ids.extend(
                (int(flow["id"]), flow["capture_id"])
                for flow in db.execute(
                    "SELECT id, capture_id FROM flows WHERE source = 'pcap' AND capture_id LIKE ? ORDER BY id",
                    (prefix,),
                ).fetchall()
            )
        capture_order: list[str] = []
        for _, capture_id in flow_ids:
            if capture_id and capture_id not in capture_order:
                capture_order.append(capture_id)
        flows_to_delete = [
            flow_id
            for flow_id, capture_id in flow_ids
            if capture_id and capture_order and capture_id != capture_order[0]
        ]
        if flows_to_delete:
            placeholders = ",".join("?" for _ in flows_to_delete)
            removed_flows += db.execute(
                f"DELETE FROM flows WHERE id IN ({placeholders})", flows_to_delete
            ).rowcount
        duplicate_ids = [int(item["id"]) for item in analyses[1:]]
        placeholders = ",".join("?" for _ in duplicate_ids)
        removed_analyses += db.execute(
            f"DELETE FROM pcap_analysis WHERE id IN ({placeholders})", duplicate_ids
        ).rowcount
        db.execute("UPDATE pcap_analysis SET sha256 = ? WHERE id = ?", (digest, oldest["id"]))

    db.execute(
        "INSERT INTO schema_migrations (migration_id, applied_at) VALUES (?, ?)",
        (migration_id, datetime.now(timezone.utc).isoformat()),
    )
    logger.info(
        "PCAP deduplication migration complete: removed %d duplicate analyses and %d duplicate flows",
        removed_analyses,
        removed_flows,
    )


def _alert_dedup_key(
    rule_id: Any,
    detection: Any,
    title: Any,
    source_ip: Any,
    destination_ip: Any,
    timestamp: Any,
    source: Any,
    window_seconds: int,
) -> str:
    try:
        parsed_timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        bucket = int(parsed_timestamp.timestamp()) // max(1, window_seconds)
    except (ValueError, TypeError):
        bucket = int(datetime.now(timezone.utc).timestamp()) // max(1, window_seconds)
    identity = "|".join(
        (
            str(rule_id or detection or title or "alert"),
            str(source_ip or ""),
            str(destination_ip or ""),
            str(bucket),
            str(source or "pcap"),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _backfill_alert_dedup_keys(db: sqlite3.Connection) -> None:
    db.execute("DROP INDEX IF EXISTS idx_alerts_dedup_key")
    rows = db.execute(
        "SELECT id, timestamp, detection, title, source_ip, destination_ip, rule_id, source, dedup_key FROM alerts ORDER BY id"
    ).fetchall()
    seen = {str(row["dedup_key"]) for row in rows if row["dedup_key"]}
    for row in rows:
        if row["dedup_key"]:
            continue
        rule = db.execute(
            "SELECT time_window FROM rules WHERE id = ? OR LOWER(name) = LOWER(?) LIMIT 1",
            (row["rule_id"], row["detection"] or ""),
        ).fetchone()
        window_seconds = max(1, int(rule["time_window"])) if rule else 60
        key = _alert_dedup_key(
            row["rule_id"],
            row["detection"],
            row["title"],
            row["source_ip"],
            row["destination_ip"],
            row["timestamp"],
            row["source"],
            window_seconds,
        )
        if key in seen:
            key = hashlib.sha256(f"{key}|legacy-alert:{row['id']}".encode("utf-8")).hexdigest()
        seen.add(key)
        db.execute("UPDATE alerts SET dedup_key = ? WHERE id = ?", (key, row["id"]))


def initialize_database() -> None:
    with connect() as db:
        _ensure_alerts_schema(db)
        _ensure_assets_schema(db)
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                summary TEXT,
                assigned_analyst TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                evidence_json TEXT DEFAULT '{}',
                notes TEXT DEFAULT ''
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                PRIMARY KEY (incident_id, alert_id)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                packet_count INTEGER DEFAULT 0,
                bytes INTEGER DEFAULT 0,
                duration REAL DEFAULT 0.0
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac_address TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                protocols TEXT DEFAULT '[]',
                packet_count INTEGER DEFAULT 0,
                traffic_volume INTEGER DEFAULT 0,
                associated_alerts INTEGER DEFAULT 0
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                severity TEXT NOT NULL,
                threshold INTEGER NOT NULL DEFAULT 0,
                time_window INTEGER NOT NULL DEFAULT 60,
                configuration_json TEXT DEFAULT '{}',
                last_tested TEXT,
                evidence TEXT DEFAULT ''
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                id TEXT PRIMARY KEY,
                interface_name TEXT,
                state TEXT NOT NULL,
                started_at TEXT,
                ended_at TEXT,
                total_packets INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                packets_per_second REAL DEFAULT 0,
                bytes_per_second REAL DEFAULT 0,
                active_flows INTEGER DEFAULT 0,
                protocol_distribution TEXT DEFAULT '{}',
                capture_errors TEXT DEFAULT '[]'
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS pcap_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                total_packets INTEGER NOT NULL,
                unique_ips INTEGER NOT NULL,
                suspicious_activity INTEGER NOT NULL,
                generated_alerts INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        migrations = {
            "alerts": {
                "dedup_key": "TEXT",
                "source": "TEXT NOT NULL DEFAULT 'pcap'",
                "analyst_notes": "TEXT NOT NULL DEFAULT ''",
                "classification": "TEXT",
                "mitre_technique": "TEXT",
                "mitre_technique_id": "TEXT",
                "mitre_technique_name": "TEXT",
            },
            "rules": {
                "mitre_technique_id": "TEXT",
                "mitre_technique_name": "TEXT",
                "rule_type": "TEXT NOT NULL DEFAULT 'builtin'",
            },
            "flows": {
                "first_seen": "TEXT",
                "last_seen": "TEXT",
                "capture_id": "TEXT",
                "source": "TEXT NOT NULL DEFAULT 'pcap'",
            },
            "assets": {
                "discovery_source": "TEXT DEFAULT 'pcap'",
                "is_active": "INTEGER NOT NULL DEFAULT 1",
                "internal_external": "TEXT NOT NULL DEFAULT 'unknown'",
                "criticality": "TEXT NOT NULL DEFAULT 'normal'",
                "risk_score": "INTEGER NOT NULL DEFAULT 0",
            },
            "audit_log": {
                "result": "TEXT NOT NULL DEFAULT 'success'",
                "client_ip": "TEXT",
            },
            "incidents": {
                "closure_reason": "TEXT",
            },
            "pcap_analysis": {
                "sha256": "TEXT",
                "result_json": "TEXT NOT NULL DEFAULT '{}'",
                "protocols_json": "TEXT NOT NULL DEFAULT '{}'",
                "stored_path": "TEXT",
            },
        }
        for table_name, columns in migrations.items():
            existing = {row[1] for row in db.execute(f"PRAGMA table_info({table_name})")}
            for column_name, column_definition in columns.items():
                if column_name not in existing:
                    db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")
        _repair_duplicate_pcap_records(db)
        _backfill_alert_dedup_keys(db)
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_pcap_analysis_sha256 ON pcap_analysis(sha256) WHERE sha256 IS NOT NULL")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_dedup_key ON alerts(dedup_key) WHERE dedup_key IS NOT NULL")
        db.execute("CREATE INDEX IF NOT EXISTS idx_flows_capture_id ON flows(capture_id)")
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                author TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS suppression_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL CHECK(kind IN ('ip', 'cidr', 'rule')),
                value TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL DEFAULT 'system',
                created_at TEXT NOT NULL,
                UNIQUE(kind, value)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS rule_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                actor TEXT NOT NULL,
                changes_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS replay_sessions (
                id TEXT PRIMARY KEY,
                analysis_id INTEGER NOT NULL,
                speed REAL NOT NULL,
                state TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                error TEXT,
                result_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip)")

        default_rules = [
            {
                "name": "Port Scan",
                "description": "Detect multi-port reconnaissance across a single source IP.",
                "enabled": 1,
                "severity": "medium",
                "threshold": 20,
                "time_window": 300,
                "configuration_json": json.dumps({"min_ports": 10}),
                "id": 1,
            },
            {
                "name": "SYN Flood Indicators",
                "description": "Detect bursty SYN activity consistent with flood conditions.",
                "enabled": 1,
                "severity": "high",
                "threshold": 200,
                "time_window": 60,
                "configuration_json": json.dumps({"syn_ratio": 0.7}),
                "id": 2,
            },
            {
                "name": "ICMP Flood Indicators",
                "description": "Identify ICMP abnormality and flooding patterns.",
                "enabled": 1,
                "severity": "high",
                "threshold": 100,
                "time_window": 60,
                "configuration_json": json.dumps({"icmp_threshold": 100}),
                "id": 3,
            },
            {
                "name": "DNS Anomalies",
                "description": "Flag unusually large or repeated DNS requests.",
                "enabled": 1,
                "severity": "medium",
                "threshold": 10,
                "time_window": 120,
                "configuration_json": json.dumps({"payload_bytes": 512, "long_query_bytes": 256}),
                "id": 4,
            },
            {
                "name": "ARP Spoofing Indicators",
                "description": "Flag mismatched ARP replies and spoofing behaviour.",
                "enabled": 1,
                "severity": "high",
                "threshold": 5,
                "time_window": 60,
                "configuration_json": json.dumps({"arp_likelihood": 0.8}),
                "id": 5,
            },
            {
                "name": "Suspicious Outbound Connections",
                "description": "Detect unusual outbound traffic to uncommon ports.",
                "enabled": 1,
                "severity": "medium",
                "threshold": 5,
                "time_window": 180,
                "configuration_json": json.dumps({"unknown_ports": [23, 3389, 5900]}),
                "id": 6,
            },
        ]
        for rule in default_rules:
            db.execute(
                """
                INSERT OR IGNORE INTO rules (id, name, description, enabled, severity, threshold, time_window, configuration_json, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, '')
                """,
                (
                    rule["id"],
                    rule["name"],
                    rule["description"],
                    rule["enabled"],
                    rule["severity"],
                    rule["threshold"],
                    rule["time_window"],
                    rule["configuration_json"],
                ),
            )
            technique = MITRE_BY_RULE_NAME.get(rule["name"].lower())
            if technique:
                db.execute(
                    "UPDATE rules SET mitre_technique_id = ?, mitre_technique_name = ? WHERE LOWER(name) = LOWER(?) AND mitre_technique_id IS NULL",
                    (*technique, rule["name"]),
                )
        for rule_name, technique in MITRE_BY_RULE_NAME.items():
            db.execute(
                "UPDATE rules SET mitre_technique_id = ?, mitre_technique_name = ? WHERE LOWER(name) = LOWER(?) AND (mitre_technique_id IS NULL OR mitre_technique_name IS NULL)",
                (*technique, rule_name),
            )
        for rule in db.execute(
            "SELECT id, rule_id, detection, mitre_technique_id, mitre_technique_name FROM alerts WHERE mitre_technique_id IS NULL OR mitre_technique_name IS NULL"
        ).fetchall():
            technique = MITRE_BY_RULE_ID.get(str(rule["rule_id"] or "").lower())
            if not technique:
                technique = MITRE_BY_RULE_NAME.get(str(rule["detection"] or "").lower())
            if not technique and rule["rule_id"]:
                definition = db.execute(
                    "SELECT mitre_technique_id, mitre_technique_name FROM rules WHERE id = ?",
                    (rule["rule_id"],),
                ).fetchone()
                if definition and definition[0] and definition[1]:
                    technique = (definition[0], definition[1])
            if technique:
                db.execute(
                    "UPDATE alerts SET mitre_technique_id = ?, mitre_technique_name = ?, mitre_technique = ? WHERE id = ?",
                    (*technique, f"{technique[0]} — {technique[1]}", rule["id"]),
                )
        db.execute(
            """
            UPDATE rules SET configuration_json = ?
            WHERE id = 4 AND configuration_json = ?
            """,
            (
                json.dumps({"payload_bytes": 512, "long_query_bytes": 256}),
                json.dumps({"payload_bytes": 100}),
            ),
        )


def reset_monitoring_state() -> None:
    with LOCK, connect() as db:
        db.execute("DELETE FROM monitoring_sessions")
        db.execute("DELETE FROM settings WHERE key = 'monitoring.session_id'")


def add_audit_log(
    action: str,
    actor: str,
    details: str,
    result: str = "success",
    client_ip: str | None = None,
) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        db.execute(
            "INSERT INTO audit_log (timestamp, action, actor, details, result, client_ip) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, action, actor, details, result, client_ip),
        )


def fetch_alerts(
    limit: int = 200,
    offset: int = 0,
    severity: str | None = None,
    search: str | None = None,
    status: str | None = None,
    sort_by: str = "timestamp",
    order: str = "desc",
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    query = "SELECT * FROM alerts"
    clauses: list[str] = ["COALESCE(source, 'pcap') != 'replay'"]
    params: list[Any] = []
    if severity and severity in {"critical","high","medium","low","info","informational"}:
        clauses.append("severity = ?")
        params.append(severity)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if search:
        clauses.append("(LOWER(title) LIKE LOWER(?) OR LOWER(details) LIKE LOWER(?) OR LOWER(source_ip) LIKE LOWER(?) OR LOWER(destination_ip) LIKE LOWER(?))")
        search_term = f"%{search}%"
        params.extend([search_term, search_term, search_term, search_term])
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    sort_columns = {"timestamp": "timestamp", "severity": "severity", "status": "status", "id": "id"}
    sort_column = sort_columns.get(sort_by, "timestamp")
    sort_order = "ASC" if order.lower() == "asc" else "DESC"
    query += f" ORDER BY {sort_column} {sort_order}, id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with connect() as db:
        rows = db.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def alert_exists(alert_id: int) -> bool:
    with connect() as db:
        return db.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is not None


def _fetch_dashboard_counts(db: sqlite3.Connection) -> dict[str, Any]:
    alerts = db.execute(
        "SELECT COUNT(*), COUNT(DISTINCT source_ip) FROM alerts WHERE COALESCE(source, 'pcap') != 'replay'"
    ).fetchone()
    severity = {
        row[0]: row[1]
        for row in db.execute(
            "SELECT severity, COUNT(*) FROM alerts WHERE COALESCE(source, 'pcap') != 'replay' GROUP BY severity"
        )
    }
    latest = db.execute(
        "SELECT source_file FROM alerts WHERE COALESCE(source, 'pcap') != 'replay' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return {
        "total_alerts": int(alerts[0]),
        "severity": severity,
        "unique_sources": int(alerts[1]),
        "latest_capture": latest[0] if latest else None,
        "total_packets": int(
            db.execute("SELECT COALESCE(SUM(total_packets), 0) FROM pcap_analysis WHERE sha256 IS NOT NULL").fetchone()[0]
        ),
        "open_incidents": int(
            db.execute("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved','False Positive')").fetchone()[0]
        ),
        "active_flows": int(
            db.execute("SELECT COUNT(*) FROM flows WHERE COALESCE(source, 'pcap') != 'replay'").fetchone()[0]
        ),
    }


def fetch_stats() -> dict[str, Any]:
    with connect() as db:
        return _fetch_dashboard_counts(db)


def clear_alerts() -> int:
    with LOCK, connect() as db:
        count = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        db.execute("DELETE FROM alerts")
    return count


def update_alert(alert_id: int, **updates: Any) -> dict[str, Any] | None:
    allowed = {"status", "assigned_analyst", "classification", "analyst_notes"}
    changes = {key: value for key, value in updates.items() if key in allowed}
    if not changes:
        raise ValueError("No supported alert fields supplied")
    with LOCK, connect() as db:
        assignments = ", ".join(f"{key} = ?" for key in changes)
        cursor = db.execute(
            f"UPDATE alerts SET {assignments} WHERE id = ?",
            [*changes.values(), alert_id],
        )
        if cursor.rowcount == 0:
            return None
        row = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def add_alert_note(alert_id: int, author: str, note: str) -> dict[str, Any] | None:
    created_at = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        if not db.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone():
            return None
        cursor = db.execute(
            "INSERT INTO alert_notes (alert_id, author, note, created_at) VALUES (?, ?, ?, ?)",
            (alert_id, author, note, created_at),
        )
        row = db.execute("SELECT * FROM alert_notes WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row) if row else None


def fetch_alert_notes(alert_id: int) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY id", (alert_id,)).fetchall()
    return [dict(row) for row in rows]


def bulk_update_alerts(alert_ids: list[int], **updates: Any) -> int:
    if not alert_ids:
        return 0
    allowed = {"status", "assigned_analyst", "classification"}
    changes = {key: value for key, value in updates.items() if key in allowed}
    if not changes:
        raise ValueError("No supported alert fields supplied")
    placeholders = ",".join("?" for _ in alert_ids)
    with LOCK, connect() as db:
        assignments = ", ".join(f"{key} = ?" for key in changes)
        cursor = db.execute(
            f"UPDATE alerts SET {assignments} WHERE id IN ({placeholders})",
            [*changes.values(), *alert_ids],
        )
        return cursor.rowcount


def fetch_suppression_rules() -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM suppression_rules ORDER BY id DESC").fetchall()
    return [dict(row) for row in rows]


def create_suppression_rule(kind: str, value: str, actor: str) -> dict[str, Any]:
    created_at = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        cursor = db.execute(
            "INSERT INTO suppression_rules (kind, value, created_by, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(kind, value) DO UPDATE SET enabled = 1",
            (kind, value, actor, created_at),
        )
        row = db.execute(
            "SELECT * FROM suppression_rules WHERE kind = ? AND value = ?",
            (kind, value),
        ).fetchone()
    return dict(row) if row else {"id": cursor.lastrowid, "kind": kind, "value": value}


def is_alert_suppressed(alert: dict[str, Any]) -> bool:
    import ipaddress

    source_ip = alert.get("source_ip")
    rule_id = alert.get("rule_id")
    with connect() as db:
        rules = db.execute("SELECT kind, value FROM suppression_rules WHERE enabled = 1").fetchall()
    for row in rules:
        if row["kind"] == "rule" and str(rule_id) == row["value"]:
            return True
        if source_ip and row["kind"] == "ip" and source_ip == row["value"]:
            return True
        if source_ip and row["kind"] == "cidr":
            try:
                if ipaddress.ip_address(source_ip) in ipaddress.ip_network(row["value"], strict=False):
                    return True
            except ValueError:
                continue
    return False


def _ensure_assets_schema(db: sqlite3.Connection) -> None:
    existing_columns = {row[1] for row in db.execute("PRAGMA table_info(assets)").fetchall()}
    if not existing_columns:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac_address TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                protocols TEXT DEFAULT '[]',
                packet_count INTEGER DEFAULT 0,
                traffic_volume INTEGER DEFAULT 0,
                associated_alerts INTEGER DEFAULT 0,
                discovery_source TEXT DEFAULT 'pcap',
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        return
    for column_name, column_sql in {
        "discovery_source": "TEXT DEFAULT 'pcap'",
        "is_active": "INTEGER NOT NULL DEFAULT 1",
    }.items():
        if column_name not in existing_columns:
            db.execute(f"ALTER TABLE assets ADD COLUMN {column_name} {column_sql}")


def sync_asset_inventory_from_observed_data(flows: list[dict[str, Any]], source: str = "pcap") -> None:
    if not flows:
        return
    observed: dict[str, dict[str, Any]] = {}
    for flow in flows:
        for ip_key in ("source_ip", "destination_ip"):
            ip_value = flow.get(ip_key)
            if not ip_value:
                continue
            entry = observed.setdefault(
                ip_value,
                {
                    "packet_count": 0,
                    "traffic_volume": 0,
                    "protocols": set(),
                    "last_seen": flow.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                },
            )
            entry["packet_count"] += int(flow.get("packet_count", 1) or 1)
            entry["traffic_volume"] += int(flow.get("bytes", 0) or 0)
            entry["protocols"].add((flow.get("protocol") or "unknown").upper())
            if flow.get("timestamp") and flow["timestamp"] > entry["last_seen"]:
                entry["last_seen"] = flow["timestamp"]
    now = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        for ip_value, values in observed.items():
            existing = db.execute(
                "SELECT * FROM assets WHERE ip = ? ORDER BY last_seen DESC LIMIT 1",
                (ip_value,),
            ).fetchone()
            protocols = sorted(values["protocols"])
            if existing is None:
                db.execute(
                    """
                    INSERT INTO assets (ip, mac_address, first_seen, last_seen, protocols, packet_count, traffic_volume, associated_alerts, discovery_source, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 1)
                    """,
                    (
                        ip_value,
                        None,
                        values["last_seen"] or now,
                        values["last_seen"] or now,
                        json.dumps(protocols),
                        values["packet_count"],
                        values["traffic_volume"],
                        source,
                    ),
                )
                continue
            db.execute(
                """
                UPDATE assets
                SET last_seen = ?, protocols = ?, packet_count = packet_count + ?, traffic_volume = traffic_volume + ?, discovery_source = ?, is_active = 1
                WHERE ip = ?
                """,
                (
                    values["last_seen"] or existing["last_seen"],
                    json.dumps(sorted(set(json.loads(existing["protocols"]) if existing["protocols"] else []) | set(protocols))),
                    values["packet_count"],
                    values["traffic_volume"],
                    source,
                    ip_value,
                ),
            )


def fetch_overview(window: str = "24h") -> dict[str, Any]:
    with connect() as db:
        alerts = [dict(row) for row in db.execute(
            """
            SELECT * FROM alerts
            WHERE timestamp >= datetime('now', '-1 day')
              AND COALESCE(source, 'pcap') != 'replay'
            ORDER BY timestamp DESC
            LIMIT 20
            """
        )]
        severity_counts = {
            row[0]: row[1] for row in db.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE timestamp >= datetime('now', '-1 day') AND COALESCE(source, 'pcap') != 'replay' GROUP BY severity"
            )
        }
        top_sources = [
            {"label": row[0], "value": row[1]}
            for row in db.execute(
                "SELECT source_ip, COUNT(*) FROM alerts WHERE timestamp >= datetime('now', '-1 day') AND COALESCE(source, 'pcap') != 'replay' GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 5"
            )
        ]
        top_destinations = [
            {"label": row[0], "value": row[1]}
            for row in db.execute(
                "SELECT destination_ip, COUNT(*) FROM alerts WHERE timestamp >= datetime('now', '-1 day') AND COALESCE(source, 'pcap') != 'replay' GROUP BY destination_ip ORDER BY COUNT(*) DESC LIMIT 5"
            )
        ]
        protocol_counts = [
            {"label": row[0], "value": row[1]}
            for row in db.execute(
                "SELECT protocol, COUNT(*) FROM alerts WHERE timestamp >= datetime('now', '-1 day') AND COALESCE(source, 'pcap') != 'replay' GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 10"
            )
        ]
        counts = _fetch_dashboard_counts(db)
    return {
        "window": window,
        "counts": counts,
        "alerts": alerts,
        "severity_counts": severity_counts,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "protocol_counts": protocol_counts,
    }


def fetch_flows(
    limit: int = 50,
    search: str | None = None,
    protocol: str | None = None,
    include_replay: bool = False,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM flows"
    clauses: list[str] = [] if include_replay else ["COALESCE(source, 'pcap') != 'replay'"]
    params: list[Any] = []
    if search:
        clauses.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term])
    if protocol:
        clauses.append("protocol = ?")
        params.append(protocol)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with connect() as db:
        rows = db.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def upsert_alerts(alerts: list[dict[str, Any]]) -> list[int]:
    created_ids: list[int] = []
    severity_order = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    minimum_severity = get_setting("severity_threshold", "medium").lower()
    minimum_rank = severity_order.get(minimum_severity, 0)
    with LOCK, connect() as db:
        for item in alerts:
            severity = str(item.get("severity", "medium")).lower()
            if severity_order.get(severity, 0) < minimum_rank:
                continue
            if is_alert_suppressed(item):
                continue
            timestamp = item.get("timestamp") or datetime.now(timezone.utc).isoformat()
            rule_id = item.get("rule_id")
            rule_name = "DNS Anomalies" if rule_id in {"dns-anomaly", "dns-repetition"} else None
            rule = (
                db.execute(
                    "SELECT time_window, mitre_technique_id, mitre_technique_name FROM rules WHERE LOWER(name) = LOWER(?)",
                    (rule_name,),
                ).fetchone()
                if rule_name
                else (
                    db.execute(
                        "SELECT time_window, mitre_technique_id, mitre_technique_name FROM rules WHERE id = ?",
                        (rule_id,),
                    ).fetchone()
                    if rule_id
                    else None
                )
            )
            window_seconds = max(1, int(rule["time_window"])) if rule else 60
            technique = (
                (item.get("mitre_technique_id"), item.get("mitre_technique_name"))
                if item.get("mitre_technique_id") and item.get("mitre_technique_name")
                else (
                    (rule["mitre_technique_id"], rule["mitre_technique_name"])
                    if rule and rule["mitre_technique_id"] and rule["mitre_technique_name"]
                    else MITRE_BY_RULE_ID.get(str(rule_id or "").lower())
                    or MITRE_BY_RULE_NAME.get(str(item.get("detection") or "").lower())
                )
            )
            technique_id, technique_name = technique if technique else (None, None)
            technique_display = (
                f"{technique_id} — {technique_name}"
                if technique_id and technique_name
                else item.get("mitre_technique")
            )
            dedup_key = item.get("dedup_key") or _alert_dedup_key(
                rule_id,
                item.get("detection"),
                item.get("title"),
                item.get("source_ip"),
                item.get("destination_ip"),
                timestamp,
                item.get("source"),
                window_seconds,
            )
            cursor = db.execute(
                """
                INSERT OR IGNORE INTO alerts (timestamp, detection, severity, title, source_ip, destination_ip, protocol, status, details, evidence_json, source_file, rule_id, alert_type, dedup_key, source, mitre_technique, mitre_technique_id, mitre_technique_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    item.get("detection", item.get("title", "Alert")),
                    severity,
                    item.get("title", "Detected activity"),
                    item.get("source_ip"),
                    item.get("destination_ip"),
                    item.get("protocol"),
                    item.get("status", "New"),
                    item.get("details", ""),
                    json.dumps(item.get("evidence", {})),
                    item.get("source_file", "unknown"),
                    item.get("rule_id"),
                    item.get("alert_type", "pcap"),
                    dedup_key,
                    item.get("source", "pcap"),
                    technique_display,
                    technique_id,
                    technique_name,
                ),
            )
            if cursor.rowcount:
                created_ids.append(cursor.lastrowid)
    return created_ids


def save_flow_records(flows: list[dict[str, Any]], capture_id: str | None = None, source: str = "pcap") -> None:
    with LOCK, connect() as db:
        for flow in flows:
            db.execute(
                """
                INSERT INTO flows (timestamp, source_ip, destination_ip, source_port, destination_port, protocol, packet_count, bytes, duration, first_seen, last_seen, capture_id, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.get("first_seen") or flow.get("timestamp"),
                    flow.get("source_ip"),
                    flow.get("destination_ip"),
                    flow.get("source_port"),
                    flow.get("destination_port"),
                    flow.get("protocol"),
                    flow.get("packet_count", 1),
                    flow.get("bytes", 0),
                    float(flow.get("duration", 0.0) or 0.0),
                    flow.get("first_seen") or flow.get("timestamp"),
                    flow.get("last_seen") or flow.get("timestamp"),
                    capture_id,
                    source,
                ),
            )
    sync_asset_inventory_from_observed_data(flows, source)


def fetch_assets(include_replay: bool = False) -> list[dict[str, Any]]:
    with connect() as db:
        query = "SELECT * FROM assets"
        if not include_replay:
            query += " WHERE COALESCE(discovery_source, 'pcap') != 'replay'"
        rows = db.execute(query + " ORDER BY last_seen DESC LIMIT 50").fetchall()
    return [dict(row) for row in rows]


def fetch_incidents() -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute(
            "SELECT i.*, COALESCE((SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.id), 0) AS alert_count FROM incidents i ORDER BY i.updated_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_incident(incident_id: int) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return None
        incident = dict(row)
        incident["alerts"] = [
            dict(alert)
            for alert in db.execute(
                "SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = ? ORDER BY a.timestamp DESC",
                (incident_id,),
            ).fetchall()
        ]
        incident["timeline"] = [
            dict(event)
            for event in db.execute(
                "SELECT * FROM incident_timeline WHERE incident_id = ? ORDER BY created_at, id",
                (incident_id,),
            ).fetchall()
        ]
    return incident


def add_incident_timeline(incident_id: int, actor: str, action: str, details: str) -> None:
    with LOCK, connect() as db:
        db.execute(
            "INSERT INTO incident_timeline (incident_id, actor, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (incident_id, actor, action, details, datetime.now(timezone.utc).isoformat()),
        )


def create_incident(title: str, severity: str, assigned_analyst: str, summary: str, alert_ids: list[int]) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        cursor = db.execute(
            "INSERT INTO incidents (title, severity, status, summary, assigned_analyst, created_at, updated_at, evidence_json, notes) VALUES (?, ?, 'New', ?, ?, ?, ?, '{}', '')",
            (title, severity, summary or title, assigned_analyst or 'unassigned', now, now),
        )
        incident_id = cursor.lastrowid
        for alert_id in alert_ids:
            if not db.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone():
                raise ValueError(f"Alert {alert_id} does not exist")
            db.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)", (incident_id, alert_id))
        db.execute(
            "INSERT INTO incident_timeline (incident_id, actor, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (incident_id, assigned_analyst or "unassigned", "created", summary or title, now),
        )
    return {"id": incident_id, "title": title, "severity": severity, "status": "New", "summary": summary or title,
            "assigned_analyst": assigned_analyst or 'unassigned', "created_at": now, "updated_at": now, "alert_count": len(alert_ids)}


def update_incident(incident_id: int, **updates: Any) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        if not updates:
            row = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            return dict(row) if row else {}
        sets = ["updated_at = ?"]
        params: list[Any] = [now]
        for key, value in updates.items():
            if value is not None:
                sets.append(f"{key} = ?")
                params.append(value)
        params.append(incident_id)
        db.execute(f"UPDATE incidents SET {', '.join(sets)} WHERE id = ?", params)
        row = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return dict(row) if row else {}


def fetch_rules() -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM rules ORDER BY id ASC").fetchall()
    return [dict(row) for row in rows]


def fetch_rule_by_name(name: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM rules WHERE LOWER(name) = LOWER(?) LIMIT 1", (name,)).fetchone()
    return dict(row) if row else None


def fetch_rule_by_id(rule_id: int) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    return dict(row) if row else None


def update_rule(rule_id: int, **changes: Any) -> dict[str, Any]:
    with LOCK, connect() as db:
        for key, value in changes.items():
            if value is not None:
                db.execute(f"UPDATE rules SET {key} = ? WHERE id = ?", (value, rule_id))
        row = db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    return dict(row) if row else {}


def fetch_audit_logs(limit: int = 50) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_monitoring_session() -> dict[str, Any]:
    with connect() as db:
        row = db.execute("SELECT * FROM monitoring_sessions ORDER BY started_at DESC LIMIT 1").fetchone()
    if row is None:
        return {
            "id": None,
            "state": "Offline PCAP",
            "interface_name": get_setting("monitoring.interface", ""),
            "started_at": None,
            "ended_at": None,
            "total_packets": 0,
            "total_bytes": 0,
            "capture_errors": [],
        }
    return {**dict(row), "capture_errors": json.loads(row["capture_errors"]) if row["capture_errors"] else []}


def upsert_monitoring_session(
    session_id: str | None,
    interface_name: str | None,
    state: str,
    *,
    started_at: str | None = None,
    ended_at: str | None = None,
    total_packets: int = 0,
    total_bytes: int = 0,
    packets_per_second: float = 0.0,
    bytes_per_second: float = 0.0,
    active_flows: int = 0,
    protocol_distribution: dict[str, Any] | None = None,
    capture_errors: list[str] | None = None,
) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()
    if not session_id:
        with LOCK, connect() as db:
            db.execute("DELETE FROM monitoring_sessions")
        return {"id": None, "state": "Stopped", "interface_name": interface_name, "started_at": started_at, "ended_at": ended_at}
    with LOCK, connect() as db:
        db.execute(
            """
            INSERT INTO monitoring_sessions (
                id, interface_name, state, started_at, ended_at, total_packets, total_bytes,
                packets_per_second, bytes_per_second, active_flows, protocol_distribution, capture_errors
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                interface_name = excluded.interface_name,
                state = excluded.state,
                started_at = excluded.started_at,
                ended_at = excluded.ended_at,
                total_packets = excluded.total_packets,
                total_bytes = excluded.total_bytes,
                packets_per_second = excluded.packets_per_second,
                bytes_per_second = excluded.bytes_per_second,
                active_flows = excluded.active_flows,
                protocol_distribution = excluded.protocol_distribution,
                capture_errors = excluded.capture_errors
            """,
            (
                session_id,
                interface_name,
                state,
                started_at or timestamp,
                ended_at,
                total_packets,
                total_bytes,
                packets_per_second,
                bytes_per_second,
                active_flows,
                json.dumps(protocol_distribution or {}),
                json.dumps(capture_errors or []),
            ),
        )
    return {
        "id": session_id,
        "state": state,
        "interface_name": interface_name,
        "started_at": started_at or timestamp,
        "ended_at": ended_at,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "capture_errors": capture_errors or [],
    }


def fetch_system_health() -> dict[str, Any]:
    with connect() as db:
        last_alert = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        last_session = db.execute("SELECT * FROM monitoring_sessions ORDER BY started_at DESC LIMIT 1").fetchone()
    state = (last_session["state"] if last_session else "Offline PCAP")
    return {
        "backend": "Operational",
        "database": "Operational",
        "packet_capture_engine": "Operational" if state in {"Running", "Starting", "Idle"} else "Not Configured",
        "detection_engine": "Operational",
        "frontend_api_connection": "Operational",
        "websocket": "Not Configured",
        "ml_engine": "Not Configured",
        "threat_intelligence": "Not Configured",
        "last_alert_count": last_alert,
        "monitor_state": state,
    }


def get_setting(key: str, default: str = "") -> str:
    with connect() as db:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(key: str, value: str) -> str:
    with LOCK, connect() as db:
        db.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    return value


def save_pcap_analysis(file_name: str, total_packets: int, unique_ips: int, suspicious_activity: int, generated_alerts: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        db.execute(
            "INSERT INTO pcap_analysis (file_name, total_packets, unique_ips, suspicious_activity, generated_alerts, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (file_name, total_packets, unique_ips, suspicious_activity, generated_alerts, now),
        )


def get_pcap_analysis_by_hash(sha256: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM pcap_analysis WHERE sha256 = ?", (sha256,)).fetchone()
    return dict(row) if row else None


def save_pcap_analysis_result(
    file_name: str,
    total_packets: int,
    unique_ips: int,
    suspicious_activity: int,
    generated_alerts: int,
    sha256: str | None,
    result: dict[str, Any],
    protocols: dict[str, int],
    stored_path: str | None = None,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        cursor = db.execute(
            """
            INSERT INTO pcap_analysis
                (file_name, total_packets, unique_ips, suspicious_activity, generated_alerts,
                 created_at, sha256, result_json, protocols_json, stored_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_name,
                total_packets,
                unique_ips,
                suspicious_activity,
                generated_alerts,
                now,
                sha256,
                json.dumps(result),
                json.dumps(protocols),
                stored_path,
            ),
        )
        return int(cursor.lastrowid)


def fetch_pcap_analysis(analysis_id: int) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM pcap_analysis WHERE id = ?", (analysis_id,)).fetchone()
    return dict(row) if row else None


def fetch_recent_pcap_analysis(limit: int = 10) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute(
            "SELECT id, file_name, total_packets, unique_ips, suspicious_activity, generated_alerts, created_at, sha256, result_json, protocols_json FROM pcap_analysis ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_replay_session(
    replay_id: str,
    analysis_id: int,
    speed: float,
    state: str,
    *,
    ended_at: str | None = None,
    error: str | None = None,
    result: dict[str, Any] | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        db.execute(
            """
            INSERT INTO replay_sessions (id, analysis_id, speed, state, started_at, ended_at, error, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET state = excluded.state, ended_at = excluded.ended_at,
                error = excluded.error, result_json = excluded.result_json
            """,
            (
                replay_id,
                analysis_id,
                speed,
                state,
                now,
                ended_at,
                error,
                json.dumps(result or {}),
            ),
        )


def get_replay_session() -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute("SELECT * FROM replay_sessions ORDER BY started_at DESC LIMIT 1").fetchone()
    if not row:
        return None
    result = dict(row)
    result["result"] = json.loads(result.pop("result_json") or "{}")
    return result
