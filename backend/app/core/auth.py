from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.db.session import LOCK, add_audit_log, connect

ALGORITHM = "HS256"
TOKEN_MINUTES = 60
JWT_SECRET = os.environ.get("NIDS_JWT_SECRET") or secrets.token_urlsafe(48)
PASSWORD_HASHER = PasswordHasher()
BEARER = HTTPBearer(auto_error=False)


def create_password_hash(password: str) -> str:
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters long")
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def user_count() -> int:
    with connect() as db:
        return int(db.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def create_user(username: str, password: str, role: str = "analyst") -> dict[str, Any]:
    if not username or len(username) > 80 or not username.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=400, detail="Username must be 1-80 letters, numbers, hyphens, or underscores")
    if role not in {"admin", "analyst", "viewer"}:
        raise HTTPException(status_code=400, detail="Role must be admin, analyst, or viewer")
    password_hash = create_password_hash(password)
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        with connect() as db:
            cursor = db.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, password_hash, role, created_at),
            )
            user_id = cursor.lastrowid
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise HTTPException(status_code=409, detail="Username already exists") from exc
        raise
    return {"id": user_id, "username": username, "role": role, "enabled": True}


def create_initial_admin(username: str, password: str) -> dict[str, Any]:
    if not username or len(username) > 80 or not username.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(status_code=400, detail="Username must be 1-80 letters, numbers, hyphens, or underscores")
    password_hash = create_password_hash(password)
    created_at = datetime.now(timezone.utc).isoformat()
    with LOCK, connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise HTTPException(status_code=409, detail="Initial administrator is already configured")
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
            (username, password_hash, created_at),
        )
        user = {"id": cursor.lastrowid, "username": username, "role": "admin", "enabled": True}
    add_audit_log("initial_admin_created", username, "Initial administrator account configured")
    return user


def get_user(username: str) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute(
            "SELECT id, username, password_hash, role, enabled FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def issue_token(user: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_MINUTES),
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(BEARER),
) -> dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[ALGORITHM])
        username = claims.get("sub")
        if not username:
            raise ValueError("Token has no subject")
    except (JWTError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc
    user = get_user(username)
    if not user or not user["enabled"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is disabled or no longer exists")
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


def require_roles(*roles: str) -> Callable[..., dict[str, Any]]:
    def role_dependency(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        if user["role"] not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role for this operation")
        return user

    return role_dependency
