"""Password hashing, JWT creation and checking, and role-based access dependencies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .models import User

ROLES = ("admin", "analyst")
MAX_PASSWORD_BYTES = 72   # bcrypt ignores everything after 72 bytes, so refuse longer ones
MIN_PASSWORD_CHARS = 10
ALGORITHM = "HS256"
bearer = HTTPBearer(auto_error=False)


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_CHARS:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_CHARS} characters.")
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes.")


def hash_password(password: str) -> str:
    validate_password(password)
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


# A real hash to check against when the email is unknown, so a wrong email and a wrong
# password take about the same time and cannot be told apart by timing.
DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt()).decode()


def create_token(user: User, kind: str, secret: str, lifetime: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user.id), "role": user.role, "type": kind, "iat": now, "exp": now + lifetime}
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_token(token: str, secret: str, kind: str) -> dict:
    try:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub", "type"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token has expired.")
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid token.")
    if payload["type"] != kind:
        raise HTTPException(401, f"A {kind} token is required here.")
    return payload


def get_current_user(
    request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer)
) -> User:
    if creds is None:
        raise HTTPException(401, "Not authenticated.", headers={"WWW-Authenticate": "Bearer"})
    payload = decode_token(creds.credentials, request.app.state.settings.secret_key, "access")
    with request.app.state.sessionmaker() as db:
        user = db.get(User, int(payload["sub"]))
        if user is None or not user.is_active:
            raise HTTPException(401, "User no longer exists or is disabled.")
        db.expunge(user)
    return user


def require_role(*allowed: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(403, "Your role is not allowed to do this.")
        return user

    return checker


def audit(db: Session, user: User | None, action: str, detail: str = "", ip: str = "") -> None:
    from .models import AuditLog

    db.add(AuditLog(user_id=user.id if user else None, action=action, detail=detail[:2000], ip=ip))
