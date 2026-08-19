"""Autenticación F7: users, otp_codes, sessions, auth_events

Revision ID: 0005_auth
Revises: 0004_scan_cliente
Create Date: 2026-08-18
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_auth"
down_revision = "0004_scan_cliente"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("nombre", sa.String(length=200), nullable=False),
        sa.Column("rol", sa.String(length=20), nullable=False),
        sa.Column("activo", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "otp_codes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("code_hash", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_otp_codes_email", "otp_codes", ["email"])

    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"], unique=True)
    op.create_index("ix_sessions_email", "sessions", ["email"])

    op.create_table(
        "auth_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column(
            "at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.String(length=300), nullable=True),
    )
    op.create_index("ix_auth_events_email", "auth_events", ["email"])
    op.create_index("ix_auth_events_at", "auth_events", ["at"])


def downgrade() -> None:
    op.drop_index("ix_auth_events_at", table_name="auth_events")
    op.drop_index("ix_auth_events_email", table_name="auth_events")
    op.drop_table("auth_events")

    op.drop_index("ix_sessions_email", table_name="sessions")
    op.drop_index("ix_sessions_token_hash", table_name="sessions")
    op.drop_table("sessions")

    op.drop_index("ix_otp_codes_email", table_name="otp_codes")
    op.drop_table("otp_codes")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
