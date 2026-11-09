from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import get_current_user, require_roles
from app.db.session import add_audit_log, add_incident_timeline, create_incident, fetch_incident, fetch_incidents, update_incident

router = APIRouter(tags=["incidents"], dependencies=[Depends(get_current_user)])


@router.get("/incidents")
def list_incidents() -> list[dict[str, Any]]:
    return fetch_incidents()


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int) -> dict[str, Any]:
    incident = fetch_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/incidents")
def create_payload(
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    title = payload.get("title") or "Untitled incident"
    severity = payload.get("severity", "medium")
    if severity not in {"info", "low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail="Invalid incident severity")
    assigned_analyst = payload.get("assigned_analyst", user["username"])
    summary = payload.get("summary", title)
    alert_ids = payload.get("alert_ids", [])
    if not isinstance(alert_ids, list):
        raise HTTPException(status_code=400, detail="alert_ids must be a list")
    if any(not isinstance(alert_id, int) for alert_id in alert_ids):
        raise HTTPException(status_code=400, detail="alert_ids must contain integers")
    try:
        incident = create_incident(title, severity, assigned_analyst, summary, alert_ids)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    add_audit_log("incident_created", user["username"], f"Created incident {incident['id']}")
    return incident


@router.patch("/incidents/{incident_id}")
def patch_incident(
    incident_id: int,
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    updates = {k: v for k, v in payload.items() if k in {"title", "severity", "status", "assigned_analyst", "summary", "notes"}}
    if updates.get("status") == "Resolved":
        updates["closure_reason"] = payload.get("closure_reason")
        if not updates["closure_reason"]:
            raise HTTPException(status_code=400, detail="closure_reason is required when resolving an incident")
    result = update_incident(incident_id, **updates)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    add_audit_log("incident_updated", user["username"], f"Updated incident {incident_id}")
    add_incident_timeline(incident_id, user["username"], "updated", ", ".join(sorted(updates)))
    return result


@router.post("/incidents/{incident_id}/close")
def close_incident(
    incident_id: int,
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin", "analyst")),
) -> dict[str, Any]:
    reason = str(payload.get("closure_reason", "")).strip()
    if not reason:
        raise HTTPException(status_code=400, detail="closure_reason is required")
    result = update_incident(incident_id, status="Resolved", closure_reason=reason)
    if not result:
        raise HTTPException(status_code=404, detail="Incident not found")
    add_incident_timeline(incident_id, user["username"], "closed", reason)
    add_audit_log("incident_closed", user["username"], f"Closed incident {incident_id}")
    return result
