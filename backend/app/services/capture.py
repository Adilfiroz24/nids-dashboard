from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from scapy.all import AsyncSniffer, ICMP, IP, TCP, UDP

from app.db import session
from app.services.detection import inspect_packet


class CaptureWorker:
    def __init__(self, interface_name: str):
        self.id = str(uuid.uuid4())
        self.interface_name = interface_name
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.started_monotonic = time.monotonic()
        self.total_packets = 0
        self.total_bytes = 0
        self.flows: dict[tuple[str, str, int, int, str], dict[str, Any]] = {}
        self.protocol_distribution: dict[str, int] = {}
        self.errors: list[str] = []
        self.lock = threading.Lock()
        self.sniffer = AsyncSniffer(iface=interface_name, store=False, prn=self._on_packet)

    def _on_packet(self, packet: Any) -> None:
        try:
            now = datetime.now(timezone.utc).isoformat()
            byte_count = len(bytes(packet))
            protocol = "OTHER"
            flow_key = None
            flow_data = None
            if IP in packet:
                ip = packet[IP]
                if TCP in packet:
                    transport, protocol = packet[TCP], "TCP"
                    source_port, destination_port = int(transport.sport), int(transport.dport)
                elif UDP in packet:
                    transport, protocol = packet[UDP], "UDP"
                    source_port, destination_port = int(transport.sport), int(transport.dport)
                elif ICMP in packet:
                    source_port, destination_port = 0, 0
                    protocol = "ICMP"
                else:
                    source_port, destination_port = 0, 0
                flow_key = (ip.src, ip.dst, source_port, destination_port, protocol)
                flow_data = {
                    "timestamp": now,
                    "first_seen": now,
                    "last_seen": now,
                    "source_ip": ip.src,
                    "destination_ip": ip.dst,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "protocol": protocol,
                    "packet_count": 0,
                    "bytes": 0,
                    "duration": 0.0,
                }
            with self.lock:
                self.total_packets += 1
                self.total_bytes += byte_count
                self.protocol_distribution[protocol] = self.protocol_distribution.get(protocol, 0) + 1
                if flow_key and flow_data:
                    flow = self.flows.setdefault(flow_key, flow_data)
                    flow["last_seen"] = now
                    flow["packet_count"] += 1
                    flow["bytes"] += byte_count
                    flow["duration"] = max(
                        0.0,
                        (datetime.fromisoformat(now) - datetime.fromisoformat(flow["first_seen"])).total_seconds(),
                    )
                alerts = inspect_packet(packet, "live")
            for alert in alerts:
                alert["source"] = "live"
                alert["alert_type"] = "live"
            if alerts:
                session.upsert_alerts(alerts)
        except Exception as exc:
            with self.lock:
                self.errors.append(f"Packet processing error: {exc}")

    def start(self) -> None:
        self.sniffer.start()
        threading.Event().wait(0.1)
        if not self.sniffer.running:
            raise RuntimeError("Scapy capture worker did not remain active")

    def snapshot(self) -> dict[str, Any]:
        elapsed = max(time.monotonic() - self.started_monotonic, 0.001)
        with self.lock:
            return {
                "id": self.id,
                "interface_name": self.interface_name,
                "started_at": self.started_at,
                "state": "Running" if self.sniffer.running else "Failed",
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "packets_per_second": round(self.total_packets / elapsed, 2),
                "bytes_per_second": round(self.total_bytes / elapsed, 2),
                "active_flows": len(self.flows),
                "protocol_distribution": dict(self.protocol_distribution),
                "capture_errors": list(self.errors),
            }

    def stop(self) -> dict[str, Any]:
        was_running = self.sniffer.running
        if was_running:
            self.sniffer.stop(join=True)
        with self.lock:
            flows = list(self.flows.values())
        if flows:
            session.save_flow_records(flows, capture_id=self.id, source="live")
        snapshot = self.snapshot()
        snapshot["state"] = "Stopped" if was_running else "Failed"
        snapshot["ended_at"] = datetime.now(timezone.utc).isoformat()
        return snapshot


class CaptureManager:
    def __init__(self) -> None:
        self._workers: dict[str, CaptureWorker] = {}
        self._lock = threading.Lock()

    def start(self, interface_name: str) -> dict[str, Any]:
        worker = CaptureWorker(interface_name)
        with self._lock:
            if any(item.sniffer.running for item in self._workers.values()):
                raise RuntimeError("A live capture worker is already running")
        worker.start()
        with self._lock:
            self._workers[worker.id] = worker
        snapshot = worker.snapshot()
        session.upsert_monitoring_session(
            worker.id,
            interface_name,
            snapshot["state"],
            started_at=worker.started_at,
            total_packets=0,
            total_bytes=0,
        )
        return snapshot

    def get(self, session_id: str | None) -> dict[str, Any] | None:
        if not session_id:
            return None
        with self._lock:
            worker = self._workers.get(session_id)
        return worker.snapshot() if worker else None

    def stop(self, session_id: str | None) -> dict[str, Any] | None:
        if not session_id:
            return None
        with self._lock:
            worker = self._workers.pop(session_id, None)
        return worker.stop() if worker else None


capture_manager = CaptureManager()
