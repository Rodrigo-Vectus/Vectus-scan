"""initial: projects, authorizations, scans

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-10
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


analysis_type = sa.Enum(
    "biec", "bajo_nivel", "alto_nivel", name="analysis_type"
)
scan_status = sa.Enum(
    "creado", "en_cola", "corriendo", "completado", "error", name="scan_status"
)


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("client", sa.String(length=200), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "authorizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("responsible_user", sa.String(length=200), nullable=False),
        sa.Column("authorized", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("analysis_type", analysis_type, nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column(
            "project_id",
            sa.Integer(),
            sa.ForeignKey("projects.id"),
            nullable=False,
        ),
        sa.Column(
            "authorization_id",
            sa.Integer(),
            sa.ForeignKey("authorizations.id"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("scans")
    op.drop_table("authorizations")
    op.drop_table("projects")
    # Los tipos ENUM solo existen como tipos nombrados en PostgreSQL.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        scan_status.drop(bind, checkfirst=True)
        analysis_type.drop(bind, checkfirst=True)
