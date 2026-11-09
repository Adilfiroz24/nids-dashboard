from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.core.auth import get_current_user
from app.db.session import fetch_assets

router = APIRouter(tags=["assets"], dependencies=[Depends(get_current_user)])


@router.get("/assets")
def list_assets(search: str | None = Query(default=None), limit: int = Query(20, ge=1, le=200)) -> list[dict[str, object]]:
    rows = fetch_assets()
    if search:
        rows = [row for row in rows if search.lower() in str(row.get("ip", "")).lower()]
    return rows[:limit]
