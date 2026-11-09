from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str = "NIDS Monitor API"
    app_version: str = "1.0.0"
    data_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get(
                "NIDS_DATA_DIR",
                Path(__file__).resolve().parents[2] / "data",
            )
        )
    )
    allowed_origins: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            sorted(
                {
                    "http://127.0.0.1:5173",
                    "http://localhost:5173",
                    os.environ.get("NIDS_FRONTEND_ORIGIN", "").strip().rstrip("/"),
                }
                - {""}
            )
        )
    )
    upload_limit_mb: int = 50
    parse_timeout_seconds: int = 60

    def __post_init__(self) -> None:
        object.__setattr__(self, "data_dir", Path(self.data_dir))
        self.data_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
