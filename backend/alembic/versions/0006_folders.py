"""Carpetas de scans (F10): tabla folders + scans.folder_id

Revision ID: 0006_folders
Revises: 0005_auth
Create Date: 2026-08-25

`folder_id` es nullable a propósito: los scans que ya existen quedan "sin
carpeta" y siguen siendo visibles. No se define ondelete porque el endpoint
de borrado rechaza (409) las carpetas que tengan scans; la FK sin cascada es
la última línea de defensa si alguien borra por SQL.
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_folders"
down_revision = "0005_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "folders",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("nombre", sa.String(length=120), nullable=False),
        sa.Column("descripcion", sa.String(length=300), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_folders_nombre", "folders", ["nombre"], unique=True)

    # batch_alter_table: en Postgres emite los ALTER normales; en SQLite usa la
    # estrategia de copiar-y-mover, que es la única forma de agregar una FK ahí.
    # Así la migración es verificable en los dos motores.
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("folder_id", sa.Integer(), nullable=True))
        batch.create_index("ix_scans_folder_id", ["folder_id"])
        batch.create_foreign_key(
            "fk_scans_folder_id", "folders", ["folder_id"], ["id"]
        )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("fk_scans_folder_id", type_="foreignkey")
        batch.drop_index("ix_scans_folder_id")
        batch.drop_column("folder_id")
    op.drop_index("ix_folders_nombre", table_name="folders")
    op.drop_table("folders")
