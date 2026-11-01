"""Settings, read from environment variables. Nothing secret has a default."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    secret_key: str
    database_url: str = "sqlite:///./records.db"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    login_rate_limit: str = "5/minute"
    rate_limit_enabled: bool = True
    max_upload_mb: int = 25
    insert_batch_size: int = 5000

    @classmethod
    def from_env(cls) -> "Settings":
        secret = os.environ.get("SECRET_KEY", "")
        if len(secret) < 32:
            raise RuntimeError(
                "SECRET_KEY must be set to a random string of at least 32 characters, "
                "for example: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        return cls(
            secret_key=secret,
            database_url=os.environ.get("DATABASE_URL", cls.database_url),
            access_token_minutes=int(os.environ.get("ACCESS_TOKEN_MINUTES", cls.access_token_minutes)),
            refresh_token_days=int(os.environ.get("REFRESH_TOKEN_DAYS", cls.refresh_token_days)),
            login_rate_limit=os.environ.get("LOGIN_RATE_LIMIT", cls.login_rate_limit),
            rate_limit_enabled=os.environ.get("RATE_LIMIT_ENABLED", "true").lower() != "false",
            max_upload_mb=int(os.environ.get("MAX_UPLOAD_MB", cls.max_upload_mb)),
        )
