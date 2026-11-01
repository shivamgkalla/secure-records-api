"""Alembic environment.

The database URL comes from the DATABASE_URL environment variable. Tests (or any other
caller) can instead pass a live connection through `config.attributes["connection"]`.
"""

import os

from alembic import context
from sqlalchemy import create_engine

from secure_records.models import Base

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or os.environ.get("DATABASE_URL", "sqlite:///./records.db")


def _run(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied = config.attributes.get("connection")
    if supplied is not None:
        _run(supplied)
        return
    with create_engine(_url()).connect() as connection:
        _run(connection)


run_migrations_online()
