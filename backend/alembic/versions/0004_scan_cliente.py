"""scans.cliente para el informe (F4)

Revision ID: 0004_scan_cliente
Revises: 0003_findings
Create Date: 2026-08-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_scan_cliente"
down_revision = "0003_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("cliente", sa.String(length=200), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "cliente")
