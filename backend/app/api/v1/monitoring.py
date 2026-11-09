from __future__ import annotations

import json
import ipaddress
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from scapy.all import conf, get_if_list

from app.core.auth import get_current_user, require_roles
from app.db.session import (
    add_audit_log,
    add_alert_note,
    alert_exists,
    bulk_update_alerts,
    clear_alerts,
    create_suppression_rule,
    fetch_alerts,
    fetch_alert_notes,
    fetch_audit_logs,
    fetch_overview,
    fetch_stats,
    fetch_suppression_rules,
    get_monitoring_session,
    get_setting,
    set_setting,
    update_alert,
    upsert_monitoring_session,
)
from app.services.capture import capture_manager

router = APIRouter(tags=["monitoring"], dependencies=[Depends(get_current_user)])


def _describe_interfaces() -> list[dict[str, Any]]:
    interfaces = get_if_list()
    details: list[dict[str, Any]] = []
    try:
        from scapy.arch.windows import get_windows_if_list

        info_by_guid = {
            str(row.get("guid", "")).strip("{}").lower(): row
            for row in get_windows_if_list()
            if row.get("guid")
        }
    except Exception:
        info_by_guid = {}
    for name in interfaces:
        match = re.search(r"NPF_?\{?([0-9a-fA-F-]{36})\}?", name)
        guid = match.group(1).lower() if match else ""
        meta = info_by_guid.get(guid)
        if not meta:
            continue
        details.append(
            {
                "index": meta.get("index"),
                "name": name,
                "friendly_name": meta.get("name") or "Network adapter",
                "description": meta.get("description") or "Windows packet capture adapter",
                "identifier": meta.get("guid") or name,
                "status": "Permission Required" if not conf.use_pcap else "Operational",
                "ip_address": (meta.get("ips") or [None])[0] if meta.get("ips") else None,
                "mac_address": meta.get("mac") or None,
                "selected": name == get_setting("monitoring.interface", ""),
            }
        )
    return details


@router.get("/alerts")
def get_alerts(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(default=None),
    search: str | None = None,
    status: str | None = None,
    sort_by: str = Query("timestamp", pattern="^(timestamp|severity|status|id)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> list[dict[str, Any]]:
    return fetch_alerts(limit=limit, offset=offset, severity=severity, search=search, status=status, sort_by=sort_by, order=order)


@router.post("/alerts/bulk")
def bulk_alert_action(
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, int]:
    alert_ids = payload.get("alert_ids")
    if not isinstance(alert_ids, list) or not alert_ids or any(not isinstance(item, int) for item in alert_ids):
        raise HTTPException(status_code=400, detail="alert_ids must be a non-empty list of integers")
    updates = {key: payload[key] for key in ("status", "assigned_analyst", "classification") if key in payload}
    if updates.get("status") not in {None, "New", "Acknowledged", "Investigating", "False Positive", "Resolved"}:
        raise HTTPException(status_code=400, detail="Invalid alert status")
    if not updates:
        raise HTTPException(status_code=400, detail="Provide status, assigned_analyst, or classification")
    count = bulk_update_alerts(alert_ids, **updates)
    add_audit_log("alerts_bulk_updated", user["username"], f"Updated {count} alerts")
    return {"updated": count}


@router.patch("/alerts/{alert_id}")
def patch_alert(
    alert_id: int,
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    updates = {key: payload[key] for key in ("status", "assigned_analyst", "classification") if key in payload}
    if updates.get("status") not in {None, "New", "Acknowledged", "Investigating", "False Positive", "Resolved"}:
        raise HTTPException(status_code=400, detail="Invalid alert status")
    if updates.get("classification") not in {None, "true_positive", "false_positive", "benign"}:
        raise HTTPException(status_code=400, detail="Invalid alert classification")
    if not updates:
        raise HTTPException(status_code=400, detail="No supported alert fields supplied")
    result = update_alert(alert_id, **updates)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    add_audit_log("alert_updated", user["username"], f"Updated alert {alert_id}")
    return result


@router.get("/alerts/{alert_id}/notes")
def list_alert_notes(alert_id: int) -> list[dict[str, Any]]:
    if not alert_exists(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return fetch_alert_notes(alert_id)


@router.post("/alerts/{alert_id}/notes")
def create_alert_note(
    alert_id: int,
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    note = str(payload.get("note", "")).strip()
    if not note or len(note) > 4000:
        raise HTTPException(status_code=400, detail="note must be 1-4000 characters")
    result = add_alert_note(alert_id, user["username"], note)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    add_audit_log("alert_note_added", user["username"], f"Added a note to alert {alert_id}")
    return result


@router.get("/suppressions")
def list_suppressions() -> list[dict[str, Any]]:
    return fetch_suppression_rules()


@router.post("/suppressions")
def add_suppression(
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    kind = payload.get("kind")
    value = str(payload.get("value", "")).strip()
    if kind not in {"ip", "cidr", "rule"} or not value:
        raise HTTPException(status_code=400, detail="kind must be ip, cidr, or rule and value is required")
    if kind == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="value must be a valid IP address") from exc
    elif kind == "cidr":
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="value must be a valid CIDR network") from exc
    elif len(value) > 128:
        raise HTTPException(status_code=400, detail="rule identifier is too long")
    result = create_suppression_rule(kind, value, user["username"])
    add_audit_log("suppression_created", user["username"], f"Created {kind} suppression")
    return result


@router.get("/stats")
def get_stats() -> dict[str, Any]:
    return fetch_stats()


@router.get("/overview")
def get_overview(window: str = "24h") -> dict[str, Any]:
    return fetch_overview(window)


@router.delete("/alerts")
def delete_alerts(user: dict[str, Any] = Depends(require_roles("admin"))) -> dict[str, int]:
    deleted = clear_alerts()
    add_audit_log("alert_history_cleared", user["username"], f"Deleted {deleted} alerts")
    return {"deleted": deleted}


@router.get("/monitor/interfaces")
def get_monitor_interfaces() -> dict[str, Any]:
    interfaces = _describe_interfaces()
    available = bool(interfaces) and bool(conf.use_pcap)
    return {
        "available": available,
        "capture_ready": bool(conf.use_pcap),
        "interfaces": interfaces,
        "reason": "No interfaces available; live capture requires Windows Npcap or admin permissions." if not interfaces else ("Packet capture permission is required for live sniffing on this host." if not conf.use_pcap else None),
    }


@router.get("/monitor/session")
def get_monitor_session() -> dict[str, Any]:
    session_state = get_monitoring_session()
    if session_state["id"] is None:
        state = "Permission Required" if not conf.use_pcap else "Offline PCAP"
        return {
            "id": None,
            "state": state,
            "message": "Packet capture is not active in this environment. Offline PCAP ingestion remains available.",
            "interface": get_setting("monitoring.interface", ""),
        }
    if session_state["state"] not in {"Starting", "Running"}:
        return {**session_state, "message": f"Capture state is {session_state['state']}."}
    worker = capture_manager.get(session_state["id"])
    if worker:
        worker_state = worker["state"]
        upsert_monitoring_session(
            worker["id"],
            worker["interface_name"],
            worker_state,
            started_at=worker["started_at"],
            total_packets=worker["total_packets"],
            total_bytes=worker["total_bytes"],
            packets_per_second=worker["packets_per_second"],
            bytes_per_second=worker["bytes_per_second"],
            active_flows=worker["active_flows"],
            protocol_distribution=worker["protocol_distribution"],
            capture_errors=worker["capture_errors"],
        )
        if worker_state == "Running":
            return {**worker, "message": "Live capture worker is active."}
        return {**worker, "message": "Capture worker is no longer running."}
    upsert_monitoring_session(
        session_state["id"],
        session_state.get("interface_name"),
        "Failed",
        started_at=session_state.get("started_at"),
        ended_at=session_state.get("ended_at"),
        total_packets=session_state.get("total_packets", 0),
        total_bytes=session_state.get("total_bytes", 0),
        capture_errors=["Persisted session has no live capture worker."],
    )
    return {
        **session_state,
        "state": "Failed",
        "message": "No capture worker exists for this session; it is not reporting live traffic.",
    }


@router.post("/monitor/start")
def start_monitor(
    request: Request,
    interface_name: str | None = None,
    user: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    client_ip = request.client.host if request.client else None
    try:
        interfaces = get_if_list()
    except Exception as exc:
        reason = f"Could not enumerate capture interfaces: {exc}"
        add_audit_log("monitoring_start_failed", user["username"], reason, result="failure", client_ip=client_ip)
        raise HTTPException(status_code=503, detail=reason) from exc
    if not interfaces:
        reason = "No packet-capture interfaces are available."
        add_audit_log("monitoring_start_failed", user["username"], reason, result="failure", client_ip=client_ip)
        raise HTTPException(status_code=503, detail="Live capture is unavailable. Install Npcap or configure an interface and try again.")
    if not conf.use_pcap:
        reason = "Packet capture permission is required; Scapy has no active libpcap/Npcap provider."
        add_audit_log("monitoring_start_failed", user["username"], reason, result="failure", client_ip=client_ip)
        raise HTTPException(status_code=503, detail=reason)
    selected = interface_name or get_setting("monitoring.interface", interfaces[0])
    if selected not in interfaces:
        reason = f"Interface '{selected}' is not available for packet capture."
        add_audit_log("monitoring_start_failed", user["username"], reason, result="failure", client_ip=client_ip)
        raise HTTPException(status_code=400, detail=reason)
    try:
        worker = capture_manager.start(selected)
    except Exception as exc:
        reason = f"Capture worker failed to start: {exc}"
        add_audit_log("monitoring_start_failed", user["username"], reason, result="failure", client_ip=client_ip)
        raise HTTPException(status_code=503, detail=reason) from exc
    set_setting("monitoring.interface", selected)
    add_audit_log(
        "monitoring_started",
        user["username"],
        f"reason: capture worker started successfully on interface {selected}; session {worker['id']}",
        result="success",
        client_ip=client_ip,
    )
    return {**worker, "message": "Monitoring session started."}


@router.post("/monitor/stop")
def stop_monitor(
    request: Request,
    user: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    client_ip = request.client.host if request.client else None
    current = get_monitoring_session()
    session_id = current["id"] if current.get("state") in {"Starting", "Running"} else None
    stopped = capture_manager.stop(session_id)
    if stopped and session_id:
        upsert_monitoring_session(
            session_id,
            stopped.get("interface_name") or current.get("interface_name") or get_setting("monitoring.interface", ""),
            "Stopped",
            started_at=stopped.get("started_at"),
            ended_at=stopped.get("ended_at"),
            total_packets=stopped.get("total_packets", 0),
            total_bytes=stopped.get("total_bytes", 0),
            packets_per_second=stopped.get("packets_per_second", 0),
            bytes_per_second=stopped.get("bytes_per_second", 0),
            active_flows=stopped.get("active_flows", 0),
            protocol_distribution=stopped.get("protocol_distribution", {}),
            capture_errors=stopped.get("capture_errors", []),
        )
        add_audit_log(
            "monitoring_stopped",
            user["username"],
            f"reason: requested capture worker {session_id} stopped successfully",
            result="success",
            client_ip=client_ip,
        )
        return {"id": session_id, "state": "Stopped", "message": "Monitoring stopped."}
    reason = "No active capture worker was found to stop."
    add_audit_log("monitoring_stop_failed", user["username"], f"reason: {reason}", result="failure", client_ip=client_ip)
    return {"id": None, "state": "Stopped", "message": reason}


@router.get("/settings")
def get_settings() -> dict[str, Any]:
    return {
        "monitoring": {"interface": get_setting("monitoring.interface", "")},
        "retention_days": int(get_setting("retention_days", "30")),
        "severity_threshold": get_setting("severity_threshold", "medium"),
    }


@router.get("/audit")
def get_audit_logs(limit: int = Query(50, ge=1, le=200)) -> list[dict[str, Any]]:
    return fetch_audit_logs(limit=limit)


@router.post("/settings")
def save_settings(
    payload: dict[str, Any],
    request: Request,
    user: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    client_ip = request.client.host if request.client else None
    unknown = set(payload) - {"monitoring", "retention_days", "severity_threshold"}
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unsupported settings: {', '.join(sorted(unknown))}")
    values: dict[str, Any] = {}
    monitoring = payload.get("monitoring")
    if isinstance(monitoring, dict) and set(monitoring) - {"interface"}:
        raise HTTPException(status_code=400, detail="Only monitoring.interface may be saved in settings")
    if isinstance(monitoring, dict) and "interface" in monitoring:
        interface = monitoring["interface"]
        if not isinstance(interface, str) or len(interface) > 256:
            raise HTTPException(status_code=400, detail="monitoring.interface must be a string no longer than 256 characters")
        values["monitoring.interface"] = monitoring["interface"]
    if "monitoring" in payload and not isinstance(monitoring, dict):
        raise HTTPException(status_code=400, detail="monitoring must be an object")
    if "retention_days" in payload:
        retention = payload["retention_days"]
        if not isinstance(retention, int) or not 1 <= retention <= 3650:
            raise HTTPException(status_code=400, detail="retention_days must be an integer between 1 and 3650")
    if "severity_threshold" in payload and payload["severity_threshold"] not in {"info", "low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail="Invalid severity threshold")
    values.update({key: value for key, value in payload.items() if key != "monitoring"})
    changed: dict[str, dict[str, Any]] = {}
    defaults = {"severity_threshold": "medium", "retention_days": "30", "monitoring.interface": ""}
    for key, value in values.items():
        serialized = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        old_value = get_setting(key, defaults.get(key, ""))
        if old_value == serialized:
            continue
        set_setting(key, serialized)
        changed[key] = {"old": old_value, "new": value}
    if changed:
        add_audit_log("settings_updated", user["username"], json.dumps(changed, sort_keys=True), client_ip=client_ip)
    return {"saved": True, "changed": changed}
