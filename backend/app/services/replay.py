from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.db import session
from app.services.detection import ReplayCancelled, import_pcap


class ReplayManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._cancel: threading.Event | None = None
        self._current: dict[str, Any] | None = None

    def start(self, analysis_id: int, stored_path: str, file_name: str, speed: float) -> dict[str, Any]:
        capture_path = Path(stored_path)
        if not capture_path.is_file():
            raise FileNotFoundError("The stored capture file is missing")
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("A replay is already active")
            replay_id = str(uuid.uuid4())
            cancel_event = threading.Event()
            self._cancel = cancel_event
            self._current = {
                "id": replay_id,
                "analysis_id": analysis_id,
                "speed": speed,
                "state": "Starting",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "error": None,
            }
            session.save_replay_session(replay_id, analysis_id, speed, "Starting")
            self._thread = threading.Thread(
                target=self._run,
                args=(replay_id, analysis_id, capture_path, file_name, speed, cancel_event),
                name=f"pcap-replay-{replay_id[:8]}",
                daemon=True,
            )
            self._thread.start()
            return dict(self._current)

    def _run(
        self,
        replay_id: str,
        analysis_id: int,
        capture_path: Path,
        file_name: str,
        speed: float,
        cancel_event: threading.Event,
    ) -> None:
        session.save_replay_session(replay_id, analysis_id, speed, "Running")
        with self._lock:
            if self._current and self._current["id"] == replay_id:
                self._current["state"] = "Running"
        try:
            result = import_pcap(
                capture_path,
                file_name,
                source="replay",
                replay_speed=speed,
                cancel_event=cancel_event,
            )
            state = "Stopped" if cancel_event.is_set() else "Completed"
            self._finish(replay_id, analysis_id, speed, state, result=result)
        except ReplayCancelled:
            self._finish(replay_id, analysis_id, speed, "Stopped")
        except Exception as exc:
            self._finish(replay_id, analysis_id, speed, "Failed", error=str(exc))

    def _finish(
        self,
        replay_id: str,
        analysis_id: int,
        speed: float,
        state: str,
        *,
        error: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        ended_at = datetime.now(timezone.utc).isoformat()
        session.save_replay_session(
            replay_id,
            analysis_id,
            speed,
            state,
            ended_at=ended_at,
            error=error,
            result=result,
        )
        with self._lock:
            if self._current and self._current["id"] == replay_id:
                self._current.update({"state": state, "ended_at": ended_at, "error": error, "result": result or {}})

    def status(self) -> dict[str, Any]:
        with self._lock:
            if self._current:
                return dict(self._current)
        stored = session.get_replay_session()
        if stored and stored["state"] in {"Starting", "Running"}:
            stored["state"] = "Failed"
            stored["error"] = "Replay worker is no longer available."
            session.save_replay_session(
                stored["id"],
                stored["analysis_id"],
                stored["speed"],
                "Failed",
                error=stored["error"],
            )
        return stored or {"id": None, "state": "Idle"}

    def stop(self) -> dict[str, Any]:
        with self._lock:
            cancel = self._cancel
            current = dict(self._current) if self._current else None
        if not current:
            return {"id": None, "state": "Idle"}
        if current["state"] in {"Starting", "Running"} and cancel:
            cancel.set()
        return self.status()


replay_manager = ReplayManager()
