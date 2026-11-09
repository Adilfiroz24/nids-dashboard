from __future__ import annotations

import time
import hashlib
import json
from types import SimpleNamespace
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap
from fastapi.testclient import TestClient

from app import main
from app.api.v1 import monitoring
from app.db import session


def test_cors_allows_both_vite_loopback_origins():
    client = TestClient(main.app)
    for origin in ("http://127.0.0.1:5173", "http://localhost:5173"):
        response = client.get("/api/health", headers={"Origin": origin})
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin


def create_admin_headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/auth/setup",
        json={"username": "test-admin", "password": "Str0ng-test-password!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_api_health_and_alerts_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()

    client = TestClient(main.app)
    headers = create_admin_headers(client)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

    status_response = client.get("/api/stats", headers=headers)
    assert status_response.status_code == 200
    assert status_response.json()["total_alerts"] == 0

    packet_path = tmp_path / "sample.pcap"
    packet_path.write_bytes(b"\x00\x00\x00\x00")
    upload_response = client.post(
        "/api/pcap",
        headers=headers,
        files={"file": (packet_path.name, packet_path.read_bytes(), "application/octet-stream")},
    )
    assert upload_response.status_code == 400
    assert "PCAP" in upload_response.json()["detail"]

    alert_response = client.get("/api/alerts", headers=headers)
    assert alert_response.status_code == 200
    assert alert_response.json() == []


def test_settings_audit_records_only_actual_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    client = TestClient(main.app)
    headers = create_admin_headers(client)
    payload = {"severity_threshold": "high", "retention_days": 14, "monitoring": {"interface": "Ethernet"}}

    assert client.post("/api/settings", json=payload, headers=headers).json()["changed"]
    assert client.post("/api/settings", json=payload, headers=headers).json()["changed"] == {}
    events = [row for row in session.fetch_audit_logs() if row["action"] == "settings_updated"]
    assert len(events) == 1
    assert '"old": "medium"' in events[0]["details"]
    assert '"new": "high"' in events[0]["details"]


def test_failed_capture_is_not_audited_as_started(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    monkeypatch.setattr(monitoring, "get_if_list", lambda: ["\\Device\\NPF_{00000000-0000-0000-0000-000000000001}"])
    monkeypatch.setattr(monitoring.conf, "use_pcap", False)
    client = TestClient(main.app)
    headers = create_admin_headers(client)
    response = client.post("/api/monitor/start", headers=headers)
    assert response.status_code == 503
    events = session.fetch_audit_logs()
    assert any(event["action"] == "monitoring_start_failed" and event["result"] == "failure" for event in events)
    assert not any(event["action"] == "monitoring_started" for event in events)


def test_capture_state_resets_and_start_stop_attempts_are_audited(tmp_path, monkeypatch):
    database_path = tmp_path / "capture-state.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", database_path)
    main.initialize()
    session.upsert_monitoring_session("stale-session", "Ethernet", "Failed", capture_errors=["old failure"])
    session.set_setting("monitoring.session_id", "stale-session")

    main.initialize()
    assert session.get_monitoring_session()["id"] is None
    assert session.get_setting("monitoring.session_id", "") == ""

    client = TestClient(main.app)
    headers = create_admin_headers(client)
    settings_response = client.get("/api/settings", headers=headers)
    assert settings_response.status_code == 200
    assert "session_id" not in settings_response.json()["monitoring"]
    rejected = client.post(
        "/api/settings",
        headers=headers,
        json={"monitoring": {"session_id": "persisted-session"}},
    )
    assert rejected.status_code == 400

    stop_response = client.post("/api/monitor/stop", headers=headers)
    assert stop_response.status_code == 200
    stop_event = next(row for row in session.fetch_audit_logs() if row["action"] == "monitoring_stop_failed")
    assert stop_event["result"] == "failure"
    assert "reason:" in stop_event["details"]


def test_successful_capture_attempts_are_audited_with_result_and_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "capture-success.sqlite3")
    main.initialize()
    monkeypatch.setattr(monitoring, "get_if_list", lambda: ["Ethernet"])
    monkeypatch.setattr(monitoring, "conf", SimpleNamespace(use_pcap=True))

    def fake_start(interface):
        worker = {
            "id": "test-capture",
            "interface_name": interface,
            "state": "Running",
            "started_at": "2026-01-01T00:00:00+00:00",
            "total_packets": 0,
            "total_bytes": 0,
        }
        session.upsert_monitoring_session(worker["id"], interface, "Running", started_at=worker["started_at"])
        return worker

    monkeypatch.setattr(monitoring.capture_manager, "start", fake_start)
    monkeypatch.setattr(monitoring.capture_manager, "stop", lambda session_id: {"id": session_id, "state": "Stopped"})
    client = TestClient(main.app)
    headers = create_admin_headers(client)

    started = client.post("/api/monitor/start?interface_name=Ethernet", headers=headers)
    assert started.status_code == 200
    stopped = client.post("/api/monitor/stop", headers=headers)
    assert stopped.status_code == 200
    events = session.fetch_audit_logs(limit=20)
    start_event = next(row for row in events if row["action"] == "monitoring_started")
    stop_event = next(row for row in events if row["action"] == "monitoring_stopped")
    assert start_event["result"] == stop_event["result"] == "success"
    assert "reason:" in start_event["details"]
    assert "reason:" in stop_event["details"]


def test_authentication_and_viewer_role_enforcement(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    client = TestClient(main.app)
    assert client.get("/api/auth/status").json()["setup_required"] is True
    assert client.get("/api/stats").status_code == 401
    admin_headers = create_admin_headers(client)
    created = client.post(
        "/api/auth/users",
        headers=admin_headers,
        json={"username": "read-only", "password": "Another-strong-pass!", "role": "viewer"},
    )
    assert created.status_code == 200
    login = client.post("/api/auth/login", json={"username": "read-only", "password": "Another-strong-pass!"})
    viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.get("/api/stats", headers=viewer_headers).status_code == 200
    assert client.post("/api/settings", headers=viewer_headers, json={"severity_threshold": "high"}).status_code == 403
    listed_users = client.get("/api/auth/users", headers=admin_headers)
    assert listed_users.status_code == 200
    assert {item["username"] for item in listed_users.json()} == {"test-admin", "read-only"}
    assert client.get("/api/auth/users", headers=viewer_headers).status_code == 403


def test_detection_rule_edit_history_and_custom_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    client = TestClient(main.app)
    headers = create_admin_headers(client)
    rules = client.get("/api/rules", headers=headers).json()
    assert rules
    rule_id = rules[0]["id"]

    updated = client.patch(
        f"/api/rules/{rule_id}",
        headers=headers,
        json={"threshold": 12, "time_window": 90, "severity": "high"},
    )
    assert updated.status_code == 200
    assert updated.json()["threshold"] == 12
    history = client.get(f"/api/rules/{rule_id}/history", headers=headers)
    assert history.status_code == 200
    assert len(history.json()) == 1

    custom = client.post(
        "/api/rules/custom",
        headers=headers,
        json={"definition": '{"name":"Test custom rule","description":"test","severity":"medium","threshold":2,"time_window":30}'},
    )
    assert custom.status_code == 200
    assert custom.json()["name"] == "Test custom rule"
    invalid = client.post(
        "/api/rules/custom",
        headers=headers,
        json={"definition": '{"name":"Invalid","description":"test","severity":"medium","threshold":0,"time_window":30}'},
    )
    assert invalid.status_code == 400


def test_report_export_formats_and_asset_preview(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    client = TestClient(main.app)
    headers = create_admin_headers(client)

    assets = client.get("/api/reports?report_type=assets", headers=headers)
    assert assets.status_code == 200
    assert assets.json()["report_type"] == "assets"
    assert isinstance(assets.json()["records"], list)

    csv_report = client.get("/api/reports/export?report_type=assets&format=csv", headers=headers)
    assert csv_report.status_code == 200
    assert "text/csv" in csv_report.headers["content-type"]
    pdf_report = client.get("/api/reports/export?report_type=alerts&format=pdf", headers=headers)
    assert pdf_report.status_code == 200
    assert pdf_report.content.startswith(b"%PDF")

    with session.connect() as db:
        db.execute(
            """
            INSERT INTO alerts (timestamp, detection, severity, title, status, details)
            VALUES ('2020-01-01T00:00:00+00:00', 'test', 'high', 'old alert', 'New', 'old record')
            """
        )
        db.execute(
            """
            INSERT INTO incidents (title, severity, status, created_at, updated_at)
            VALUES ('old incident', 'low', 'New', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00')
            """
        )
        db.execute(
            """
            INSERT INTO assets (ip, first_seen, last_seen)
            VALUES ('192.0.2.10', '2020-01-01T00:00:00+00:00', '2020-01-01T00:00:00+00:00')
            """
        )

    start = "2099-01-01T00:00:00%2B00:00"
    end = "2100-01-01T00:00:00%2B00:00"
    for report_type in ("alerts", "incidents", "assets"):
        filtered = client.get(
            f"/api/reports?report_type={report_type}&start={start}&end={end}",
            headers=headers,
        )
        assert filtered.status_code == 200
        assert filtered.json()["records"] == []
        invalid_range = client.get(
            f"/api/reports?report_type={report_type}&start={end}&end={start}",
            headers=headers,
        )
        assert invalid_range.status_code == 400
    future_export = client.get(
        f"/api/reports/export?report_type=alerts&format=csv&start={start}&end={end}",
        headers=headers,
    )
    assert "No records matched" in future_export.text


def test_pcap_upload_deduplication_flow_and_replay(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    client = TestClient(main.app)
    headers = create_admin_headers(client)
    pcap_path = tmp_path / "integration.pcap"
    wrpcap(
        str(pcap_path),
        [Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=41000, dport=443, flags="S")],
    )
    capture = pcap_path.read_bytes()

    uploaded = client.post(
        "/api/pcap",
        headers=headers,
        files={"file": ("integration.pcap", capture, "application/vnd.tcpdump.pcap")},
    )
    assert uploaded.status_code == 200, uploaded.text
    result = uploaded.json()
    assert result["packets"] == 1
    assert result["analysis_id"]
    assert result["sha256"] == hashlib.sha256(capture).hexdigest()

    duplicate = client.post(
        "/api/pcap",
        headers=headers,
        files={"file": ("renamed.pcap", capture, "application/vnd.tcpdump.pcap")},
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert duplicate.json()["analysis_id"] == result["analysis_id"]
    assert len(session.fetch_recent_pcap_analysis(limit=20)) == 1

    flows = client.get("/api/traffic/flows", headers=headers)
    assert flows.status_code == 200
    assert any(flow["source_ip"] == "192.0.2.10" and flow["destination_port"] == 443 for flow in flows.json())

    replay_response = client.post(
        f"/api/pcap/{result['analysis_id']}/replay?speed=100",
        headers=headers,
    )
    assert replay_response.status_code == 200, replay_response.text
    for _ in range(100):
        replay_status = client.get("/api/monitor/replay/status", headers=headers).json()
        if replay_status["state"] in {"Completed", "Failed", "Stopped"}:
            break
        time.sleep(0.02)
    assert replay_status["state"] == "Completed", replay_status


def test_pcap_cleanup_migration_deduplicates_verified_bytes_once(tmp_path, monkeypatch, caplog):
    database_path = tmp_path / "duplicate-pcaps.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", database_path)
    monkeypatch.setattr(session, "DB_PATH", database_path)
    main.initialize()
    capture = tmp_path / "same-content.pcap"
    wrpcap(
        str(capture),
        [Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=41000, dport=443)],
    )
    digest = hashlib.sha256(capture.read_bytes()).hexdigest()
    with session.connect() as db:
        db.execute("DELETE FROM schema_migrations WHERE migration_id = ?", ("2026-11-pcap-raw-sha256-dedup-cleanup",))
        db.execute("DROP INDEX IF EXISTS idx_pcap_analysis_sha256")
        for legacy_hash in ("a" * 64, "b" * 64):
            db.execute(
                """
                INSERT INTO pcap_analysis
                    (file_name, total_packets, unique_ips, suspicious_activity, generated_alerts,
                     created_at, sha256, result_json, protocols_json, stored_path)
                VALUES (?, 1, 2, 0, 0, ?, ?, ?, '{}', ?)
                """,
                ("same-content.pcap", "2026-01-01T00:00:00+00:00", legacy_hash, json.dumps({"flows": 1}), str(capture)),
            )
            db.execute(
                """
                INSERT INTO flows
                    (timestamp, source_ip, destination_ip, protocol, packet_count, bytes, capture_id, source)
                VALUES (?, ?, ?, 'TCP', 1, 60, ?, 'pcap')
                """,
                ("2026-01-01T00:00:00+00:00", "192.0.2.10", "198.51.100.20", f"pcap:{legacy_hash}:1"),
            )
        db.execute(
            """
            INSERT INTO alerts (timestamp, detection, severity, title, source_ip, destination_ip, status, details)
            VALUES ('2026-01-01T00:00:00+00:00', 'Legacy rule', 'high', 'Legacy alert', '192.0.2.10', '198.51.100.20', 'New', 'legacy')
            """
        )

    with caplog.at_level("INFO"):
        main.initialize()
    main.initialize()
    with session.connect() as db:
        analyses = db.execute("SELECT id, sha256 FROM pcap_analysis").fetchall()
        flow_count = db.execute("SELECT COUNT(*) FROM flows WHERE source = 'pcap'").fetchone()[0]
        alert = db.execute("SELECT dedup_key FROM alerts WHERE title = 'Legacy alert'").fetchone()
    assert len(analyses) == 1
    assert analyses[0]["sha256"] == digest
    assert flow_count == 1
    assert alert["dedup_key"]
    assert "removed 1 duplicate analyses and 1 duplicate flows" in caplog.text


def test_legacy_alert_migration_is_idempotent_and_preserves_rows(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy.sqlite3"
    monkeypatch.setattr(main, "DB_PATH", database_path)
    monkeypatch.setattr(session, "DB_PATH", database_path)
    with session.connect() as db:
        db.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                status TEXT,
                details TEXT
            )
            """
        )
        db.execute(
            "INSERT INTO alerts (timestamp, severity, title, source_ip, destination_ip, protocol, status, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("2025-01-01T00:00:00+00:00", "high", "Existing alert", "192.0.2.1", "198.51.100.2", "TCP", "New", "legacy row"),
        )

    main.initialize()
    main.initialize()
    with session.connect() as db:
        rows = db.execute("SELECT id, title, details, source FROM alerts").fetchall()
        columns = {row["name"] for row in db.execute("PRAGMA table_info(alerts)")}
    assert len(rows) == 1
    assert rows[0]["title"] == "Existing alert"
    assert rows[0]["details"] == "legacy row"
    assert rows[0]["source"] == "pcap"
    assert {"dedup_key", "mitre_technique", "analyst_notes"}.issubset(columns)
