import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class AnalysisType(str, enum.Enum):
    """Los tres tipos de análisis del producto. Solo BIEC se implementa ahora."""

    biec = "biec"
    bajo_nivel = "bajo_nivel"
    alto_nivel = "alto_nivel"


class ScanStatus(str, enum.Enum):
    """Ciclo de vida de un scan.

    En la Fase 1 un scan solo puede quedar en `creado`. Los estados de
    ejecución (`en_cola`, `corriendo`, `completado`, `error`) se definen ya
    para no migrar el enum de nuevo en la Fase 2, pero todavía no se usan.
    """

    creado = "creado"
    en_cola = "en_cola"
    corriendo = "corriendo"
    completado = "completado"
    error = "error"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    client: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(back_populates="project")


class Authorization(Base):
    """Registro del principio rector: 'cuento con permiso escrito para
    escanear este activo'. Ningún scan puede existir sin uno de estos,
    y `authorized` debe ser True (se valida en la API y aquí como default)."""

    __tablename__ = "authorizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    responsible_user: Mapped[str] = mapped_column(String(200), nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(back_populates="authorization")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    analysis_type: Mapped[AnalysisType] = mapped_column(
        SAEnum(AnalysisType, name="analysis_type"), nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.creado,
    )

    # FKs NOT NULL: el esquema mismo impide un scan sin proyecto ni autorización.
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id"), nullable=False
    )
    authorization_id: Mapped[int] = mapped_column(
        ForeignKey("authorizations.id"), nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # F2: tiempos de ejecución y estimación (segundos).
    estimated_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    project: Mapped["Project"] = relationship(back_populates="scans")
    authorization: Mapped["Authorization"] = relationship(back_populates="scans")
    stages: Mapped[list["ScanStage"]] = relationship(
        back_populates="scan",
        order_by="ScanStage.order",
        cascade="all, delete-orphan",
    )


# Estados de etapa y de herramienta (VARCHAR simple, no enum de PG).
STAGE_PENDIENTE = "pendiente"
STAGE_CORRIENDO = "corriendo"
STAGE_COMPLETADA = "completada"
STAGE_ERROR = "error"


class ScanStage(Base):
    """Una de las 5 etapas del BIEC para un scan concreto."""

    __tablename__ = "scan_stages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"), nullable=False, index=True
    )
    order: Mapped[int] = mapped_column(Integer, nullable=False)
    key: Mapped[str] = mapped_column(String(50), nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=STAGE_PENDIENTE
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    scan: Mapped["Scan"] = relationship(back_populates="stages")
    tool_runs: Mapped[list["ToolRun"]] = relationship(
        back_populates="stage",
        order_by="ToolRun.id",
        cascade="all, delete-orphan",
    )


class ToolRun(Base):
    """Ejecución de una herramienta dentro de una etapa. Guarda el comando,
    el código de salida y la ruta a la salida cruda (parseada en F3)."""

    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stage_id: Mapped[int] = mapped_column(
        ForeignKey("scan_stages.id"), nullable=False, index=True
    )
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=STAGE_PENDIENTE
    )
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    stage: Mapped["ScanStage"] = relationship(back_populates="tool_runs")
