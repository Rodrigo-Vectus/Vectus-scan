"""findings: hallazgos normalizados (F3)

Revision ID: 0003_findings
Revises: 0002_biec_engine
Create Date: 2026-08-11
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_findings"
down_revision = "0002_biec_engine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("titulo", sa.String(length=300), nullable=False),
        sa.Column("severidad", sa.String(length=20), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=120), nullable=True),
        sa.Column("sistema_afectado", sa.String(length=500), nullable=True),
        sa.Column("evidencia", sa.Text(), nullable=True),
        sa.Column("herramienta_origen", sa.String(length=120), nullable=False),
        sa.Column("cve", sa.String(length=200), nullable=False),
        sa.Column("cwe", sa.String(length=120), nullable=True),
        sa.Column("recomendacion", sa.Text(), nullable=True),
        sa.Column("mas_info", sa.Text(), nullable=True),
        sa.Column("estado", sa.String(length=20), nullable=False),
        sa.Column("ocurrencias", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("dedup_key", sa.String(length=300), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
