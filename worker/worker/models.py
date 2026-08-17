"""Modelos espejo para el worker.

El backend (`backend/app/models.py`) es la ÚNICA fuente de verdad del
esquema; Alembic lo migra. Acá solo mapeamos las columnas que el worker
necesita leer/escribir. Un test (test_schema_drift) verifica que cada
columna espejo exista en el modelo del backend, para detectar divergencias.

Los estados se escriben como strings; `scans.status` es un enum en Postgres
y acepta el texto de la etiqueta sin problema.
"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from worker.db import Base


class Authorization(Base):
    __tablename__ = "authorizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(500))
    authorized: Mapped[bool] = mapped_column(Boolean)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20))
    authorization_id: Mapped[int] = mapped_column(ForeignKey("authorizations.id"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanStage(Base):
    __tablename__ = "scan_stages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    order: Mapped[int] = mapped_column(Integer)
    key: Mapped[str] = mapped_column(String(50))
    label: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stage_id: Mapped[int] = mapped_column(ForeignKey("scan_stages.id"))
    tool: Mapped[str] = mapped_column(String(50))
    command: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    raw_path: Mapped[str | None] = mapped_column(String(500))
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    titulo: Mapped[str] = mapped_column(String(300))
    severidad: Mapped[str] = mapped_column(String(20))
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(120))
    sistema_afectado: Mapped[str | None] = mapped_column(String(500))
    evidencia: Mapped[str | None] = mapped_column(Text)
    herramienta_origen: Mapped[str] = mapped_column(String(120))
    cve: Mapped[str] = mapped_column(String(200))
    cwe: Mapped[str | None] = mapped_column(String(120))
    recomendacion: Mapped[str | None] = mapped_column(Text)
    mas_info: Mapped[str | None] = mapped_column(Text)
    estado: Mapped[str] = mapped_column(String(20))
    ocurrencias: Mapped[int] = mapped_column(Integer)
    dedup_key: Mapped[str] = mapped_column(String(300))
