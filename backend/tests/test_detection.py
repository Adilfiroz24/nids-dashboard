from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, wrpcap
from app import main
from app.db import session
from app.main import import_pcap, inspect_packet
from app.services.detection import import_pcap as run_detection


def test_telnet_is_flagged_as_high():
    packet = Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/TCP(sport=40000, dport=23, flags="S")
    results = inspect_packet(packet, "safe-fixture.pcap")
    assert len(results) == 1
    assert results[0]["severity"] == "high"
    assert results[0]["source_ip"] == "192.0.2.10"


def test_default_rules_and_alerts_have_mitre_technique_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "mitre.sqlite3")
    main.initialize()
    rules = session.fetch_rules()
    assert len(rules) >= 6
    assert all(rule["mitre_technique_id"] and rule["mitre_technique_name"] for rule in rules[:6])

    packet = Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=40000, dport=23, flags="S")
    alert_ids = session.upsert_alerts(inspect_packet(packet, "mitre.pcap"))
    assert alert_ids
    alert = session.fetch_alerts(limit=1)[0]
    assert alert["mitre_technique_id"] == "T1021"
    assert alert["mitre_technique_name"] == "Remote Services"


def test_ssh_is_info_and_regular_https_is_not_flagged():
    ssh = Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/TCP(sport=40000, dport=22, flags="S")
    https = Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/TCP(sport=40000, dport=443, flags="S")
    assert inspect_packet(ssh, "safe-fixture.pcap")[0]["severity"] == "info"
    assert inspect_packet(https, "safe-fixture.pcap") == []


def test_import_pcap_persists_detected_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    capture = tmp_path / "safe-fixture.pcap"
    wrpcap(str(capture), [Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/UDP(sport=53000, dport=53)/("x"*220)])
    result = import_pcap(capture, capture.name)
    assert result["packets"] == 1
    assert result["alerts"] == 0


def test_dns_query_and_response_are_not_automatically_malicious():
    dns_query = Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/UDP(sport=53000, dport=53)/("x" * 64)
    dns_response = Ether()/IP(src="198.51.100.20", dst="192.0.2.10")/UDP(sport=53, dport=53000)/("y" * 128)
    assert inspect_packet(dns_query, "normal-dns.pcap") == []
    assert inspect_packet(dns_response, "normal-dns.pcap") == []


def test_large_dns_response_triggers_alert_at_threshold():
    payload = Ether()/IP(src="198.51.100.20", dst="192.0.2.10")/UDP(sport=53, dport=53000)/("z" * 600)
    results = inspect_packet(payload, "large-dns.pcap")
    assert len(results) == 1
    assert results[0]["severity"] in {"medium", "high"}
    assert results[0]["rule_id"] == "dns-anomaly"


def test_repetitive_dns_queries_are_flagged(tmp_path):
    packets = [
        Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/UDP(sport=53000 + i, dport=53)/("x" * 190)
        for i in range(5)
    ]
    pcap_file = tmp_path / "repeat_dns.pcap"
    wrpcap(str(pcap_file), packets)
    result = import_pcap(pcap_file, pcap_file.name)
    assert result["alerts"] == 0


def test_dns_repetition_uses_persisted_rule_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    session.update_rule(4, threshold=5, time_window=120, severity="high")
    pcap_file = tmp_path / "repeat_dns_configured.pcap"
    packets = [
        Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/UDP(sport=53000 + i, dport=53)/("x" * 190)
        for i in range(5)
    ]
    wrpcap(str(pcap_file), packets)
    result = import_pcap(pcap_file, pcap_file.name)
    assert result["alerts"] == 1
    stored = session.fetch_alerts(limit=10)
    assert stored[0]["severity"] == "high"
    assert '"threshold": 5' in stored[0]["evidence_json"]


def test_same_pcap_hash_is_processed_once(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    capture = tmp_path / "same.pcap"
    wrpcap(str(capture), [
        Ether()/IP(src="192.0.2.10", dst="198.51.100.20")/TCP(sport=40000, dport=23, flags="S")
    ])
    first = import_pcap(capture, capture.name)
    second = import_pcap(capture, capture.name)
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    assert session.fetch_stats()["total_packets"] == 1
    assert len(session.fetch_flows(limit=10)) == 1
    assert len(session.fetch_assets()) == 2


def test_replay_does_not_persist_or_change_dashboard_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    capture = tmp_path / "replay-only.pcap"
    wrpcap(
        str(capture),
        [
            Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=41000 + i, dport=23, flags="S")
            for i in range(5)
        ],
    )
    imported = import_pcap(capture, capture.name)
    before_stats = session.fetch_stats()
    before_flows = session.fetch_flows(limit=50)
    before_assets = session.fetch_assets()
    before_alerts = session.fetch_alerts(limit=50)
    before_history = session.fetch_recent_pcap_analysis(limit=20)

    replay_result = run_detection(
        capture,
        capture.name,
        source="replay",
        replay_speed=100,
    )

    assert replay_result["packets"] == 5
    assert replay_result["alerts"] > 0
    assert session.fetch_stats() == before_stats
    assert session.fetch_flows(limit=50) == before_flows
    assert session.fetch_assets() == before_assets
    assert session.fetch_alerts(limit=50) == before_alerts
    assert session.fetch_recent_pcap_analysis(limit=20) == before_history
    assert imported["packets"] == before_stats["total_packets"]


def test_severity_threshold_is_applied_before_persistence(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.sqlite3")
    main.initialize()
    session.set_setting("severity_threshold", "high")
    ids = session.upsert_alerts([{
        "timestamp": "2026-11-08T00:00:00+00:00",
        "severity": "medium",
        "title": "below threshold",
        "details": "test",
        "source_ip": "192.0.2.1",
        "destination_ip": "198.51.100.2",
        "rule_id": "test-rule",
    }])
    assert ids == []
    assert session.fetch_alerts(limit=10) == []
