from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from app.api.v1.auth import router as auth_router
from app.api.v1.assets import router as assets_router
from app.api.v1.health import router as health_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.monitoring import router as monitoring_router
from app.api.v1.reports import router as reports_router
from app.api.v1.rules import router as rules_router
from app.api.v1.traffic import router as traffic_router
from app.core.config import settings
from app.core.logging import configure_logging
from app.core.security import configure_cors
from app.db import session
from app.services.detection import import_pcap as _import_pcap
from app.services.detection import inspect_packet as _inspect_packet

DB_PATH = session.DB_PATH

configure_logging()
session.initialize_database()


@asynccontextmanager
async def lifespan(_: FastAPI):
    session.reset_monitoring_state()
    yield


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
configure_cors(app)

app.include_router(health_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(monitoring_router, prefix="/api")
app.include_router(traffic_router, prefix="/api")
app.include_router(assets_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(rules_router, prefix="/api")
app.include_router(reports_router, prefix="/api")


def initialize() -> None:
    session.DB_PATH = DB_PATH
    session.initialize_database()
    session.reset_monitoring_state()


def inspect_packet(packet: Any, source_file: str) -> list[dict[str, str]]:
    return _inspect_packet(packet, source_file)


def import_pcap(path: str | Path, display_name: str) -> dict[str, int]:
    session.DB_PATH = DB_PATH
    return _import_pcap(path, display_name)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
