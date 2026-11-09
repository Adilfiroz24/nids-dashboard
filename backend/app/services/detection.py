from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Any

from fastapi import HTTPException
from scapy.all import ICMP, IP, TCP, UDP, PcapReader

from app.core.config import settings
from app.db import session


class ReplayCancelled(Exception):
    pass


logger = logging.getLogger(__name__)

def _packet_timestamp(packet: Any) -> str:
    return datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()


def _rule_settings(name: str) -> tuple[dict[str, Any], str, int, int]:
    rule = session.fetch_rule_by_name(name)
    if not rule:
        return {}, "medium", 10, 120
    try:
        config = json.loads(rule.get("configuration_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        config = {}
    config["_enabled"] = bool(rule.get("enabled", 1))
    return config, str(rule.get("severity") or "medium").lower(), max(1, int(rule.get("threshold") or 10)), max(1, int(rule.get("time_window") or 120))


def _evaluate_dns_packet(packet: Any, source_file: str) -> list[dict[str, Any]]:
    if UDP not in packet or (packet[UDP].dport != 53 and packet[UDP].sport != 53):
        return []
    udp = packet[UDP]
    payload = bytes(udp.payload)
    payload_len = len(payload)
    if payload_len == 0:
        return []
    is_query = int(udp.dport) == 53
    is_response = int(udp.sport) == 53
    if not is_query and not is_response:
        return []
    config, severity, _, _ = _rule_settings("DNS Anomalies")
    if not config.get("_enabled", True):
        return []
    response_threshold = max(512, int(config.get("payload_bytes", 512)))
    query_threshold = max(256, int(config.get("long_query_bytes", 256)))
    threshold = query_threshold if is_query else response_threshold
    if payload_len <= threshold:
        return []
    title = "Unusually long DNS query" if is_query else "Large DNS response"
    details = (
        f"DNS query payload is {payload_len} bytes, exceeding the configured {query_threshold}-byte query threshold."
        if is_query
        else f"DNS response payload is {payload_len} bytes, exceeding the configured {response_threshold}-byte response threshold."
    )
    return [{
        "timestamp": _packet_timestamp(packet),
        "severity": severity,
        "detection": "DNS anomalies",
        "title": title,
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": "UDP",
        "status": "New",
        "details": details,
        "source_file": source_file,
        "rule_id": "dns-anomaly",
        "evidence": {
            "payload_bytes": payload_len,
            "threshold_bytes": threshold,
            "dport": int(udp.dport),
            "sport": int(udp.sport),
            "is_query": is_query,
            "is_response": is_response,
        },
    }]


def inspect_packet(packet: Any, source_file: str) -> list[dict[str, Any]]:
    if IP not in packet:
        return []

    ip = packet[IP]
    proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else str(ip.proto)
    alerts: list[dict[str, Any]] = []

    def emit(severity: str, title: str, details: str, detection: str, rule_id: str | None = None, evidence: dict[str, Any] | None = None) -> None:
        alerts.append(
            {
                "timestamp": _packet_timestamp(packet),
                "severity": severity,
                "detection": detection,
                "title": title,
                "source_ip": ip.src,
                "destination_ip": ip.dst,
                "protocol": proto,
                "status": "New",
                "details": details,
                "source_file": source_file,
                "rule_id": rule_id,
                "evidence": evidence or {},
            }
        )

    if TCP in packet:
        tcp = packet[TCP]
        if int(tcp.dport) in {23, 2323}:
            emit(
                "high",
                "Telnet connection observed",
                f"TCP destination port {tcp.dport} is commonly used for unencrypted remote access.",
                "Telnet connection observed",
                rule_id="port-scan",
                evidence={"dport": int(tcp.dport), "flags": str(tcp.flags)},
            )
        if int(tcp.dport) == 22 and "S" in str(tcp.flags):
            emit(
                "info",
                "SSH connection attempt",
                "TCP SYN observed to destination port 22.",
                "SSH connection attempt",
                rule_id="ssh-monitor",
                evidence={"dport": 22, "flags": str(tcp.flags)},
            )
        if int(tcp.dport) in {3389, 5900} and "S" in str(tcp.flags):
            emit(
                "medium",
                "Remote desktop connection attempt",
                f"TCP SYN observed to destination port {tcp.dport}.",
                "Remote desktop connection attempt",
                rule_id="rdp-monitor",
                evidence={"dport": int(tcp.dport), "flags": str(tcp.flags)},
            )

    if UDP in packet:
        udp = packet[UDP]
        dns_alerts = _evaluate_dns_packet(packet, source_file)
        if dns_alerts:
            alerts.extend(dns_alerts)
        if int(udp.dport) in {5353, 1900}:
            emit(
                "info",
                "Service discovery traffic",
                f"UDP multicast or service discovery traffic was observed on port {udp.dport}.",
                "Service discovery traffic",
                rule_id="service-discovery",
                evidence={"dport": int(udp.dport)},
            )

    if ICMP in packet and ip.dst.startswith("224."):
        emit(
            "medium",
            "ICMP multicast probe",
            "ICMP communication to a multicast address can indicate reconnaissance or network scanning.",
            "ICMP flood indicators",
            rule_id="icmp-flood",
            evidence={"destination": ip.dst},
        )

    return alerts


def _evaluate_custom_threshold_rules(
    rules: list[dict[str, Any]],
    packet_observations: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    source_file: str,
) -> list[dict[str, Any]]:
    generated: list[dict[str, Any]] = []
    for rule in rules:
        if rule.get("rule_type") != "threshold_count" or not rule.get("enabled"):
            continue
        try:
            config = json.loads(rule.get("configuration_json") or "{}")
        except json.JSONDecodeError:
            logger.warning("Skipping custom rule %s with invalid stored configuration", rule.get("id"))
            continue
        entity = config.get("entity")
        field = config.get("field")
        expected = config.get("value")
        observations = packet_observations if entity == "packets" else flows if entity == "flows" else []
        matching = [item for item in observations if item.get(field) == expected]
        matching.sort(key=lambda item: item["_time"])
        window_seconds = max(1, int(rule.get("time_window") or 60))
        threshold = max(1, int(rule.get("threshold") or 1))
        left = 0
        maximum_count = 0
        maximum_end = 0
        for right, item in enumerate(matching):
            while item["_time"] - matching[left]["_time"] > window_seconds:
                left += 1
            count = right - left + 1
            if count > maximum_count:
                maximum_count = count
                maximum_end = right
        if maximum_count < threshold:
            continue
        right = maximum_end
        left = right - maximum_count + 1
        matched = matching[left : right + 1]
        latest = matched[-1]
        generated.append(
            {
                "timestamp": latest.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "severity": str(rule.get("severity") or "medium").lower(),
                "detection": rule["name"],
                "title": rule["name"],
                "source_ip": latest.get("source_ip"),
                "destination_ip": latest.get("destination_ip"),
                "protocol": latest.get("protocol"),
                "status": "New",
                "details": (
                    f"{maximum_count} {entity} matched {field}={expected!r} within "
                    f"{window_seconds} seconds (threshold {threshold})."
                ),
                "source_file": source_file,
                "rule_id": str(rule["id"]),
                "evidence": {
                    "entity": entity,
                    "field": field,
                    "value": expected,
                    "count": maximum_count,
                    "threshold": threshold,
                    "window_seconds": window_seconds,
                },
            }
        )
    return generated


def import_pcap(
    path: str | Path,
    display_name: str,
    source: str = "pcap",
    replay_speed: float | None = None,
    cancel_event: Event | None = None,
    capture_hash: str | None = None,
) -> dict[str, Any]:
    capture_hash = capture_hash or hashlib.sha256(Path(path).read_bytes()).hexdigest()
    existing = session.get_pcap_analysis_by_hash(capture_hash) if source == "pcap" else None
    if existing:
        try:
            result = json.loads(existing.get("result_json") or "{}")
        except json.JSONDecodeError:
            result = {}
        return {**result, "duplicate": True, "analysis_id": existing["id"]}

    packet_count = 0
    alerts: list[dict[str, Any]] = []
    flow_map: dict[tuple[str, str, int, int, str], dict[str, Any]] = {}
    dns_query_times: dict[tuple[str, str], list[float]] = defaultdict(list)
    protocol_counts: dict[str, int] = defaultdict(int)
    top_talker_bytes: dict[str, int] = defaultdict(int)
    timeline_counts: dict[str, int] = defaultdict(int)
    packet_observations: list[dict[str, Any]] = []
    parse_started = time.monotonic()
    previous_packet_time: float | None = None
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if cancel_event and cancel_event.is_set():
                    raise ReplayCancelled()
                if time.monotonic() - parse_started > settings.parse_timeout_seconds:
                    raise HTTPException(status_code=408, detail="PCAP analysis exceeded the configured time limit")
                packet_time = float(packet.time)
                if replay_speed is not None and previous_packet_time is not None:
                    delay = max(0.0, packet_time - previous_packet_time) / replay_speed
                    if cancel_event:
                        if cancel_event.wait(min(delay, 2.0)):
                            raise ReplayCancelled()
                    else:
                        time.sleep(min(delay, 2.0))
                previous_packet_time = packet_time
                packet_count += 1
                timestamp = _packet_timestamp(packet)
                protocol = "OTHER"
                if IP not in packet:
                    protocol_counts[protocol] += 1
                    continue
                ip = packet[IP]
                if TCP in packet:
                    transport = packet[TCP]
                    proto = "TCP"
                    sport = int(transport.sport)
                    dport = int(transport.dport)
                elif UDP in packet:
                    transport = packet[UDP]
                    proto = "UDP"
                    sport = int(transport.sport)
                    dport = int(transport.dport)
                    if dport == 53:
                        dns_query_times[(ip.src, ip.dst)].append(float(packet.time))
                elif ICMP in packet:
                    proto = "ICMP"
                    sport = 0
                    dport = 0
                else:
                    sport = 0
                    dport = 0
                packet_observations.append(
                    {
                        "_time": packet_time,
                        "timestamp": timestamp,
                        "source_ip": ip.src,
                        "destination_ip": ip.dst,
                        "source_port": sport,
                        "destination_port": dport,
                        "protocol": proto,
                    }
                )
                protocol_counts[proto] += 1
                packet_size = len(bytes(packet))
                top_talker_bytes[ip.src] += packet_size
                bucket = datetime.fromtimestamp(float(packet.time), timezone.utc).strftime("%Y-%m-%dT%H:00Z")
                timeline_counts[bucket] += 1
                key = (ip.src, ip.dst, sport, dport, proto)
                flow = flow_map.setdefault(
                    key,
                    {
                        "timestamp": timestamp,
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "source_ip": ip.src,
                        "destination_ip": ip.dst,
                        "source_port": sport,
                        "destination_port": dport,
                        "protocol": proto,
                        "packet_count": 0,
                        "bytes": 0,
                        "duration": 0.0,
                    },
                )
                flow["packet_count"] += 1
                flow["bytes"] += packet_size
                flow["last_seen"] = timestamp
                flow["duration"] = max(0.0, float(packet.time) - datetime.fromisoformat(flow["first_seen"]).timestamp())
                alerts.extend(inspect_packet(packet, display_name))
    except (HTTPException, ReplayCancelled):
        raise
    except Exception as exc:  # pragma: no cover - validated by API route
        raise HTTPException(status_code=400, detail=f"Could not read PCAP: {exc}") from exc

    if packet_count == 0:
        raise HTTPException(status_code=400, detail="PCAP contains no packets")

    dns_config, dns_severity, dns_threshold, dns_window = _rule_settings("DNS Anomalies")
    if dns_config.get("_enabled", True):
        for (source_ip, destination_ip), timestamps in dns_query_times.items():
            timestamps.sort()
            max_count = 0
            left = 0
            for right, current in enumerate(timestamps):
                while current - timestamps[left] > dns_window:
                    left += 1
                max_count = max(max_count, right - left + 1)
            if max_count < dns_threshold:
                continue
            alerts.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": dns_severity,
                    "detection": "DNS anomalies",
                    "title": "Repeated DNS queries from a single host",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "protocol": "UDP",
                    "status": "New",
                    "details": f"{source_ip} generated {max_count} DNS queries to {destination_ip} within the configured {dns_window}-second window (threshold {dns_threshold}).",
                    "source_file": display_name,
                    "rule_id": "dns-repetition",
                    "evidence": {"query_count": max_count, "threshold": dns_threshold, "window_seconds": dns_window, "source_ip": source_ip, "destination_ip": destination_ip},
                    "source": source,
                }
            )

    flows = list(flow_map.values())
    custom_rules = session.fetch_rules()
    alerts.extend(_evaluate_custom_threshold_rules(custom_rules, packet_observations, flows, display_name))
    for item in alerts:
        item["source"] = source
    alert_ids = session.upsert_alerts(alerts) if alerts and source != "replay" else []
    if flows and source != "replay":
        session.save_flow_records(
            flows,
            capture_id=f"{source}:{capture_hash}:{time.time_ns()}",
            source=source,
        )
    unique_ips = len({flow["source_ip"] for flow in flows} | {flow["destination_ip"] for flow in flows})
    result: dict[str, Any] = {
        "packets": packet_count,
        "alerts": len(alert_ids) if source != "replay" else len(alerts),
        "flows": len(flows),
        "unique_ips": unique_ips,
        "protocols": dict(protocol_counts),
        "top_talkers": sorted(
            ({"ip": ip, "bytes": byte_count} for ip, byte_count in top_talker_bytes.items()),
            key=lambda row: row["bytes"],
            reverse=True,
        )[:10],
        "timeline": [{"hour": hour, "packets": count} for hour, count in sorted(timeline_counts.items())],
        "sha256": capture_hash if source == "pcap" else None,
        "duplicate": False,
        "source": source,
    }
    if source == "pcap":
        analysis_id = session.save_pcap_analysis_result(
            display_name,
            packet_count,
            unique_ips,
            len(alert_ids),
            len(alert_ids),
            capture_hash,
            result,
            dict(protocol_counts),
            str(Path(path).resolve()),
        )
        result["analysis_id"] = analysis_id
        with session.connect() as db:
            db.execute("UPDATE pcap_analysis SET result_json = ? WHERE id = ?", (json.dumps(result), analysis_id))
    return result
