"""users, snapshots and records

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("password_hash", sa.String(100), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "snapshots",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("uploaded_by", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("uploaded_at", sa.DateTime, nullable=False),
        sa.Column("rows_loaded", sa.Integer, nullable=False),
        sa.Column("rows_rejected", sa.Integer, nullable=False),
    )

    op.create_table(
        "records",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("snapshot_id", sa.Integer, sa.ForeignKey("snapshots.id"), nullable=False),
        sa.Column("external_id", sa.String(40), nullable=False),
        sa.Column("full_name", sa.String(120), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("phone", sa.String(20), nullable=False),
        sa.Column("national_id", sa.String(20), nullable=False),
        sa.Column("city", sa.String(80), nullable=False),
        sa.Column("balance", sa.Numeric(14, 2), nullable=False),
    )
    op.create_index("ix_records_snapshot_external", "records", ["snapshot_id", "external_id"])


def downgrade() -> None:
    op.drop_index("ix_records_snapshot_external", table_name="records")
    op.drop_table("records")
    op.drop_table("snapshots")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
