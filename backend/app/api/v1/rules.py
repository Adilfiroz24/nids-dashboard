from __future__ import annotations

import json
import ipaddress
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException

from app.core.auth import get_current_user, require_roles
from app.db.session import add_audit_log, connect, fetch_rule_by_id, fetch_rules, update_rule

router = APIRouter(tags=["rules"], dependencies=[Depends(get_current_user)])


@router.get("/rules")
def list_rules() -> list[dict[str, Any]]:
    return fetch_rules()


@router.patch("/rules/{rule_id}")
def patch_rule(
    rule_id: int,
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    allowed = {"enabled", "severity", "threshold", "time_window", "description", "configuration_json", "evidence"}
    updates = {k: v for k, v in payload.items() if k in allowed}
    if not updates:
        raise HTTPException(status_code=400, detail="No valid rule fields to update")
    if "threshold" in updates and (not isinstance(updates["threshold"], int) or updates["threshold"] < 1):
        raise HTTPException(status_code=400, detail="threshold must be a positive integer")
    if "time_window" in updates and (not isinstance(updates["time_window"], int) or updates["time_window"] < 1):
        raise HTTPException(status_code=400, detail="time_window must be a positive integer")
    if "severity" in updates and updates["severity"] not in {"info", "low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail="Invalid rule severity")
    if "configuration_json" in updates:
        try:
            config = json.loads(updates["configuration_json"]) if isinstance(updates["configuration_json"], str) else updates["configuration_json"]
        except (TypeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=400, detail="configuration_json must contain a JSON object") from exc
        if not isinstance(config, dict):
            raise HTTPException(status_code=400, detail="configuration_json must contain a JSON object")
        updates["configuration_json"] = json.dumps(config, sort_keys=True)
    previous = fetch_rule_by_id(rule_id)
    if not previous:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    updated = update_rule(rule_id, **updates)
    changes = {key: {"old": previous.get(key), "new": updated.get(key)} for key in updates if previous.get(key) != updated.get(key)}
    if changes:
        with connect() as db:
            db.execute(
                "INSERT INTO rule_history (rule_id, actor, changes_json, created_at) VALUES (?, ?, ?, datetime('now'))",
                (rule_id, user["username"], json.dumps(changes, sort_keys=True)),
            )
        add_audit_log("rule_updated", user["username"], f"Updated rule {rule_id}")
    return updated


@router.get("/rules/{rule_id}/history")
def rule_history(rule_id: int) -> list[dict[str, Any]]:
    with connect() as db:
        rows = db.execute("SELECT * FROM rule_history WHERE rule_id = ? ORDER BY id DESC", (rule_id,)).fetchall()
    return [dict(row) for row in rows]


@router.post("/rules/custom")
def create_custom_rule(
    payload: dict[str, Any],
    user: dict[str, Any] = Depends(require_roles("admin")),
) -> dict[str, Any]:
    raw = payload.get("definition")
    if not isinstance(raw, str) or not raw.strip():
        raise HTTPException(status_code=400, detail="definition must be a JSON or YAML document")
    try:
        definition = json.loads(raw) if raw.lstrip().startswith("{") else yaml.safe_load(raw)
    except (ValueError, yaml.YAMLError) as exc:
        raise HTTPException(status_code=400, detail="Rule definition is invalid JSON/YAML") from exc
    if not isinstance(definition, dict):
        raise HTTPException(status_code=400, detail="Rule definition must be an object")
    allowed = {"name", "description", "type", "severity", "threshold", "time_window", "enabled", "configuration"}
    unknown = set(definition) - allowed
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unsupported rule fields: {', '.join(sorted(unknown))}")
    required = allowed - {"enabled"}
    missing = required - set(definition)
    if missing:
        raise HTTPException(status_code=400, detail=f"Rule definition requires: {', '.join(sorted(missing))}")
    if definition["type"] != "threshold_count":
        raise HTTPException(status_code=400, detail="type must be threshold_count")
    if not isinstance(definition["name"], str) or not definition["name"].strip() or len(definition["name"]) > 120:
        raise HTTPException(status_code=400, detail="name must be a non-empty string up to 120 characters")
    if not isinstance(definition["description"], str) or not definition["description"].strip() or len(definition["description"]) > 1000:
        raise HTTPException(status_code=400, detail="description must be a non-empty string up to 1000 characters")
    if not isinstance(definition["severity"], str) or definition["severity"] not in {"info", "low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail="Invalid rule severity")
    if type(definition["threshold"]) is not int or definition["threshold"] < 1:
        raise HTTPException(status_code=400, detail="threshold must be a positive integer")
    if type(definition["time_window"]) is not int or definition["time_window"] < 1:
        raise HTTPException(status_code=400, detail="time_window must be a positive integer")
    if "enabled" in definition and type(definition["enabled"]) is not bool:
        raise HTTPException(status_code=400, detail="enabled must be a boolean")
    configuration = definition["configuration"]
    if not isinstance(configuration, dict) or set(configuration) != {"entity", "field", "value"}:
        raise HTTPException(
            status_code=400,
            detail="configuration must contain exactly entity, field, and value",
        )
    entity = configuration["entity"]
    field = configuration["field"]
    value = configuration["value"]
    if not isinstance(entity, str) or entity not in {"packets", "flows"}:
        raise HTTPException(status_code=400, detail="configuration.entity must be packets or flows")
    field_types = {
        "source_ip": str,
        "destination_ip": str,
        "source_port": int,
        "destination_port": int,
        "protocol": str,
    }
    if not isinstance(field, str) or field not in field_types:
        raise HTTPException(status_code=400, detail="Unsupported configuration.field")
    if type(value) is not field_types[field]:
        raise HTTPException(status_code=400, detail=f"configuration.value must be {field_types[field].__name__}")
    if field in {"source_ip", "destination_ip"}:
        try:
            configuration["value"] = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="IP field value must be a valid IP address") from exc
    elif field in {"source_port", "destination_port"} and not 0 <= value <= 65535:
        raise HTTPException(status_code=400, detail="Port field value must be between 0 and 65535")
    elif field == "protocol":
        if value.upper() not in {"TCP", "UDP", "ICMP", "OTHER"}:
            raise HTTPException(status_code=400, detail="Protocol value must be TCP, UDP, ICMP, or OTHER")
        configuration["value"] = value.upper()
    with connect() as db:
        cursor = db.execute(
            "INSERT INTO rules (name, description, enabled, severity, threshold, time_window, configuration_json, rule_type) VALUES (?, ?, ?, ?, ?, ?, ?, 'threshold_count')",
            (
                definition["name"].strip(),
                definition["description"].strip(),
                int(definition.get("enabled", True)),
                definition["severity"],
                definition["threshold"],
                definition["time_window"],
                json.dumps(configuration, sort_keys=True),
            ),
        )
        rule = db.execute("SELECT * FROM rules WHERE id = ?", (cursor.lastrowid,)).fetchone()
    add_audit_log("rule_created", user["username"], f"Created custom rule {rule['id']}")
    return dict(rule)
