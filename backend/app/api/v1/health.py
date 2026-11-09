from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.auth import get_current_user
from app.core.config import settings
from app.db.session import fetch_system_health

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
    }


@router.get("/ready")
def ready() -> dict[str, str]:
    return {"status": "ready"}


@router.get("/system/health", dependencies=[Depends(get_current_user)])
def system_health() -> dict[str, object]:
    return fetch_system_health()
