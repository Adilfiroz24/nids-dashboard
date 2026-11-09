from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.auth import (
    create_initial_admin,
    create_user,
    get_current_user,
    get_user,
    issue_token,
    user_count,
    verify_password,
    require_roles,
)
from app.db.session import add_audit_log
from app.db.session import connect

router = APIRouter(tags=["authentication"])


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(Credentials):
    role: str = Field(default="analyst")


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _token_response(user: dict[str, object]) -> dict[str, object]:
    return {
        "access_token": issue_token(user),
        "token_type": "bearer",
        "expires_in": 3600,
        "user": {key: user[key] for key in ("id", "username", "role")},
    }


@router.get("/auth/status")
def auth_status() -> dict[str, object]:
    return {"setup_required": user_count() == 0}


@router.post("/auth/setup")
def setup_admin(payload: Credentials, request: Request) -> dict[str, object]:
    user = create_initial_admin(payload.username, payload.password)
    add_audit_log("login", user["username"], "Administrator signed in after setup", client_ip=_client_ip(request))
    return _token_response(user)


@router.post("/auth/login")
def login(payload: Credentials, request: Request) -> dict[str, object]:
    user = get_user(payload.username)
    if not user or not user["enabled"] or not verify_password(payload.password, user["password_hash"]):
        add_audit_log(
            "login_failed",
            payload.username,
            "Invalid credentials",
            result="failure",
            client_ip=_client_ip(request),
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")
    add_audit_log("login", user["username"], "User authenticated", client_ip=_client_ip(request))
    return _token_response(user)


@router.get("/auth/me")
def current_user(user: dict[str, object] = Depends(get_current_user)) -> dict[str, object]:
    return user


@router.get("/auth/users", dependencies=[Depends(require_roles("admin", "analyst"))])
def list_users() -> list[dict[str, object]]:
    with connect() as db:
        rows = db.execute(
            "SELECT id, username, role FROM users WHERE enabled = 1 ORDER BY username COLLATE NOCASE"
        ).fetchall()
    return [dict(row) for row in rows]


@router.post("/auth/users", dependencies=[Depends(require_roles("admin"))])
def add_user(payload: UserCreate, request: Request, actor: dict[str, object] = Depends(get_current_user)) -> dict[str, object]:
    user = create_user(payload.username, payload.password, payload.role)
    add_audit_log("user_created", str(actor["username"]), f"Created {user['role']} user {user['username']}", client_ip=_client_ip(request))
    return user
