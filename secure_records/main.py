"""The API. Create it with `create_app()`; run it with
`uvicorn secure_records.main:create_app --factory`."""

from __future__ import annotations

import csv
import io
from datetime import timedelta
from typing import Iterator

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import create_engine, func, or_, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from . import __version__
from .config import Settings
from .ingest import REQUIRED, UploadError, load_snapshot
from .masking import record_to_dict
from .models import AuditLog, Base, Record, Snapshot, User
from .security import (
    DUMMY_HASH,
    ROLES,
    audit,
    create_token,
    decode_token,
    get_current_user,
    hash_password,
    require_role,
    verify_password,
)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=200)


class RefreshIn(BaseModel):
    refresh_token: str


class UserIn(BaseModel):
    email: EmailStr
    password: str = Field(max_length=200)
    role: str


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as db:
        yield db


def csv_safe(value) -> str:
    """Stop spreadsheet programs from running a cell as a formula (CSV injection)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="Secure Records API", version=__version__)

    kwargs = {}
    if settings.database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in settings.database_url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(settings.database_url, **kwargs)
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = sessionmaker(engine, expire_on_commit=False)

    limiter = Limiter(key_func=get_remote_address, enabled=settings.rate_limit_enabled)
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def too_many(request: Request, exc: RateLimitExceeded):
        from fastapi.responses import JSONResponse

        return JSONResponse({"detail": "Too many attempts. Try again in a minute."}, status_code=429)

    def ip_of(request: Request) -> str:
        return request.client.host if request.client else ""

    # ---------------------------------------------------------------- auth
    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.post("/auth/login")
    @limiter.limit(settings.login_rate_limit)
    def login(request: Request, body: LoginIn, db: Session = Depends(get_db)):
        user = db.scalar(select(User).where(User.email == body.email.lower()))
        ok = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
        if not (user and ok and user.is_active):
            audit(db, None, "login_failed", f"email={body.email.lower()}", ip_of(request))
            db.commit()
            raise HTTPException(401, "Incorrect email or password.")
        audit(db, user, "login_ok", ip=ip_of(request))
        db.commit()
        return _token_pair(user, settings)

    @app.post("/auth/refresh")
    def refresh(body: RefreshIn, db: Session = Depends(get_db)):
        payload = decode_token(body.refresh_token, settings.secret_key, "refresh")
        user = db.get(User, int(payload["sub"]))
        if user is None or not user.is_active:
            raise HTTPException(401, "User no longer exists or is disabled.")
        return _token_pair(user, settings)   # sliding window: each refresh issues a new pair

    @app.get("/auth/me")
    def me(user: User = Depends(get_current_user)):
        return {"id": user.id, "email": user.email, "role": user.role}

    @app.post("/users", status_code=201)
    def create_user(
        body: UserIn, request: Request, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)
    ):
        if body.role not in ROLES:
            raise HTTPException(422, f"role must be one of: {', '.join(ROLES)}")
        email = body.email.lower()
        if db.scalar(select(User.id).where(User.email == email)):
            raise HTTPException(409, "A user with this email already exists.")
        try:
            password_hash = hash_password(body.password)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        user = User(email=email, password_hash=password_hash, role=body.role)
        db.add(user)
        audit(db, admin, "user_created", f"email={email} role={body.role}", ip_of(request))
        db.commit()
        return {"id": user.id, "email": user.email, "role": user.role}

    # ----------------------------------------------------------- snapshots
    @app.post("/snapshots", status_code=201)
    async def upload(
        request: Request,
        file: UploadFile = File(...),
        admin: User = Depends(require_role("admin")),
        db: Session = Depends(get_db),
    ):
        raw = await file.read(settings.max_upload_mb * 1024 * 1024 + 1)
        if len(raw) > settings.max_upload_mb * 1024 * 1024:
            raise HTTPException(413, f"File is larger than {settings.max_upload_mb} MB.")
        try:
            result = load_snapshot(db, raw, file.filename or "upload.csv", admin.id, settings.insert_batch_size)
        except UploadError as exc:
            db.rollback()
            audit(db, admin, "upload_rejected", f"{file.filename}: {exc}", ip_of(request))
            db.commit()
            raise HTTPException(422, str(exc)) from exc
        audit(db, admin, "upload", f"snapshot={result.snapshot_id} loaded={result.rows_loaded} "
              f"rejected={result.rows_rejected}", ip_of(request))
        db.commit()
        return {
            "snapshot_id": result.snapshot_id,
            "rows_loaded": result.rows_loaded,
            "rows_rejected": result.rows_rejected,
            "first_errors": result.errors,
        }

    @app.get("/snapshots")
    def snapshots(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
        rows = db.scalars(select(Snapshot).order_by(Snapshot.id.desc())).all()
        return [
            {"id": s.id, "filename": s.filename, "uploaded_at": s.uploaded_at.isoformat(),
             "rows_loaded": s.rows_loaded, "rows_rejected": s.rows_rejected}
            for s in rows
        ]

    # ------------------------------------------------------------- records
    def _query(db: Session, snapshot_id: int | None, q: str | None):
        if snapshot_id is None:
            snapshot_id = db.scalar(select(func.max(Snapshot.id)))
            if snapshot_id is None:
                raise HTTPException(404, "No data has been uploaded yet.")
        elif db.get(Snapshot, snapshot_id) is None:
            raise HTTPException(404, f"Snapshot {snapshot_id} does not exist.")
        stmt = select(Record).where(Record.snapshot_id == snapshot_id)
        if q:
            stmt = stmt.where(
                or_(Record.external_id == q, Record.city.icontains(q, autoescape=True),
                    Record.full_name.icontains(q, autoescape=True))
            )
        return snapshot_id, stmt.order_by(Record.id)

    def _allow_unmasked(unmasked: bool, user: User) -> None:
        if unmasked and user.role != "admin":
            raise HTTPException(403, "Only admins can view unmasked personal data.")

    @app.get("/records")
    def records(
        request: Request,
        snapshot_id: int | None = None,
        q: str | None = Query(None, max_length=80),
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        unmasked: bool = False,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        _allow_unmasked(unmasked, user)
        snapshot_id, stmt = _query(db, snapshot_id, q)
        total = db.scalar(select(func.count()).select_from(stmt.subquery()))
        page = db.scalars(stmt.limit(limit).offset(offset)).all()
        if unmasked:
            audit(db, user, "unmasked_view", f"snapshot={snapshot_id} q={q!r} rows={len(page)}", ip_of(request))
            db.commit()
        return {"snapshot_id": snapshot_id, "total": total, "limit": limit, "offset": offset,
                "items": [record_to_dict(r, unmasked) for r in page]}

    @app.get("/records/export")
    def export(
        request: Request,
        snapshot_id: int | None = None,
        q: str | None = Query(None, max_length=80),
        unmasked: bool = False,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ):
        _allow_unmasked(unmasked, user)
        snapshot_id, stmt = _query(db, snapshot_id, q)
        audit(db, user, "export", f"snapshot={snapshot_id} q={q!r} unmasked={unmasked}", ip_of(request))
        db.commit()
        make_session = request.app.state.sessionmaker
        columns = ["id", "snapshot_id", *REQUIRED]

        def stream() -> Iterator[str]:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(columns)
            yield buf.getvalue()
            with make_session() as session:   # own session: the request's one is closed by now
                for rec in session.scalars(stmt.execution_options(yield_per=1000)):
                    buf.seek(0)
                    buf.truncate()
                    d = record_to_dict(rec, unmasked)
                    writer.writerow([csv_safe(d[c]) for c in columns])
                    yield buf.getvalue()

        return StreamingResponse(
            stream(), media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="records_snapshot_{snapshot_id}.csv"'},
        )

    # --------------------------------------------------------------- audit
    @app.get("/audit")
    def audit_log(
        limit: int = Query(100, ge=1, le=500),
        action: str | None = None,
        _: User = Depends(require_role("admin")),
        db: Session = Depends(get_db),
    ):
        stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        return [
            {"id": a.id, "at": a.created_at.isoformat(), "user_id": a.user_id, "action": a.action,
             "detail": a.detail, "ip": a.ip}
            for a in db.scalars(stmt)
        ]

    return app


def _token_pair(user: User, settings: Settings) -> dict:
    return {
        "access_token": create_token(user, "access", settings.secret_key, timedelta(minutes=settings.access_token_minutes)),
        "refresh_token": create_token(user, "refresh", settings.secret_key, timedelta(days=settings.refresh_token_days)),
        "token_type": "bearer",
    }


def init_schema(app: FastAPI) -> None:
    """Create tables directly. For tests and quick local runs; real deployments use Alembic."""
    Base.metadata.create_all(app.state.engine)
