"""The Alembic migrations must build exactly the schema the models describe."""

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from secure_records.models import Base

ROOT = Path(__file__).resolve().parent.parent


def _config(connection) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.attributes["connection"] = connection
    return cfg


def test_upgrade_matches_models_and_downgrade_works(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    with engine.begin() as conn:
        command.upgrade(_config(conn), "head")
        diffs = compare_metadata(MigrationContext.configure(conn), Base.metadata)
        assert diffs == [], f"models and migrations disagree: {diffs}"
        assert set(inspect(conn).get_table_names()) == {"users", "snapshots", "records", "audit_log", "alembic_version"}

        command.downgrade(_config(conn), "0001")
        assert "audit_log" not in inspect(conn).get_table_names()
        command.downgrade(_config(conn), "base")
        assert set(inspect(conn).get_table_names()) <= {"alembic_version"}
