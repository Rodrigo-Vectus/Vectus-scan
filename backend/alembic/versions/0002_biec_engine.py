"""biec engine: scan timing columns + scan_stages + tool_runs

Revision ID: 0002_biec_engine
Revises: 0001_initial
Create Date: 2026-08-10
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_biec_engine"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("estimated_seconds", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "scan_stages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("order", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=50), nullable=False),
        sa.Column("label", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_stages_scan_id", "scan_stages", ["scan_id"])

    op.create_table(
        "tool_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("stage_id", sa.Integer(), sa.ForeignKey("scan_stages.id"), nullable=False),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("raw_path", sa.String(length=500), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_tool_runs_stage_id", "tool_runs", ["stage_id"])


def downgrade() -> None:
    op.drop_index("ix_tool_runs_stage_id", table_name="tool_runs")
    op.drop_table("tool_runs")
    op.drop_index("ix_scan_stages_scan_id", table_name="scan_stages")
    op.drop_table("scan_stages")
    op.drop_column("scans", "finished_at")
    op.drop_column("scans", "started_at")
    op.drop_column("scans", "estimated_seconds")
