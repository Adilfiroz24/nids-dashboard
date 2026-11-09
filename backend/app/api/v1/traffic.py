from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from starlette.requests import Request

from app.core.auth import get_current_user, require_roles
from app.db import session
from app.core.config import settings
from app.db.session import add_audit_log, fetch_flows, fetch_pcap_analysis, fetch_recent_pcap_analysis, get_pcap_analysis_by_hash
from app.services.detection import import_pcap

router = APIRouter(tags=["traffic"], dependencies=[Depends(get_current_user)])
_UPLOADS_BY_CLIENT: dict[str, list[float]] = {}
_UPLOAD_LOCK = threading.Lock()
_ANALYSIS_LOCK = threading.Lock()
_PCAP_MAGIC = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("0a0d0d0a"),
}


def _validate_magic(contents: bytes) -> None:
    if len(contents) < 4 or contents[:4] not in _PCAP_MAGIC:
        raise HTTPException(status_code=400, detail="File content is not a valid PCAP or PCAPNG capture")


def _check_upload_rate(client_ip: str) -> None:
    now = time.monotonic()
    with _UPLOAD_LOCK:
        recent = [item for item in _UPLOADS_BY_CLIENT.get(client_ip, []) if now - item < 60]
        if len(recent) >= 10:
            raise HTTPException(status_code=429, detail="PCAP upload rate limit exceeded; try again in one minute")
        recent.append(now)
        _UPLOADS_BY_CLIENT[client_ip] = recent


@router.post("/pcap")
async def upload_pcap(
    request: Request,
    file: UploadFile = File(...),
    user: dict[str, object] = Depends(require_roles("admin", "analyst")),
) -> dict[str, object]:
    client_ip = request.client.host if request.client else "unknown"
    _check_upload_rate(client_ip)
    name = Path(file.filename or "capture.pcap").name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:128] or "capture.pcap"
    if not name.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Upload a .pcap or .pcapng file")

    contents = await file.read((settings.upload_limit_mb * 1024 * 1024) + 1)
    if len(contents) > settings.upload_limit_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="PCAP is larger than the upload limit")
    _validate_magic(contents)

    capture_hash = hashlib.sha256(contents).hexdigest()
    with _ANALYSIS_LOCK:
        existing = get_pcap_analysis_by_hash(capture_hash)
        if existing:
            try:
                result = json.loads(existing.get("result_json") or "{}")
            except json.JSONDecodeError:
                result = {}
            return {**result, "duplicate": True, "analysis_id": existing["id"]}

        capture_directory = session.DB_PATH.parent / "captures"
        capture_directory.mkdir(parents=True, exist_ok=True)
        capture_path = capture_directory / f"{capture_hash}{Path(name).suffix.lower()}"
        capture_path.write_bytes(contents)
        try:
            return import_pcap(capture_path, name, capture_hash=capture_hash)
        except Exception:
            capture_path.unlink(missing_ok=True)
            raise


@router.get("/pcap/history")
def pcap_history(limit: int = Query(10, ge=1, le=100)) -> list[dict[str, object]]:
    return fetch_recent_pcap_analysis(limit=limit)


@router.post("/pcap/{analysis_id}/replay")
def replay_analysis(
    analysis_id: int,
    speed: float = Query(1.0, gt=0, le=100),
    user: dict[str, object] = Depends(require_roles("admin", "analyst")),
) -> dict[str, object]:
    analysis = fetch_pcap_analysis(analysis_id)
    if not analysis or not analysis.get("stored_path"):
        raise HTTPException(status_code=404, detail="Stored capture is unavailable for replay")
    from app.services.replay import replay_manager

    try:
        result = replay_manager.start(analysis_id, analysis["stored_path"], analysis["file_name"], speed)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    add_audit_log("pcap_replay_started", str(user["username"]), f"Replaying capture analysis {analysis_id} at {speed}x")
    return result


@router.get("/monitor/replay/status")
def replay_status() -> dict[str, object]:
    from app.services.replay import replay_manager

    return replay_manager.status()


@router.post("/monitor/replay/stop")
def stop_replay(user: dict[str, object] = Depends(require_roles("admin", "analyst"))) -> dict[str, object]:
    from app.services.replay import replay_manager

    result = replay_manager.stop()
    add_audit_log("pcap_replay_stopped", str(user["username"]), f"Replay state is {result['state']}")
    return result


@router.get("/traffic/flows")
def get_flows(
    limit: int = Query(50, ge=1, le=500),
    search: str | None = None,
    protocol: str | None = None,
):
    return fetch_flows(limit=limit, search=search, protocol=protocol)


@router.get("/traffic/summary")
def traffic_summary() -> dict[str, object]:
    flows = fetch_flows(limit=20)
    total_bytes = sum(int(item.get("bytes", 0) or 0) for item in flows)
    return {
        "total_flows": len(flows),
        "total_bytes": total_bytes,
        "recent_packets": sum(int(item.get("packet_count", 0) or 0) for item in flows),
        "pcap_history": fetch_recent_pcap_analysis(limit=10),
    }
