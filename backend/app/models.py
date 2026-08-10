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

    project: Mapped["Project"] = relationship(back_populates="scans")
    authorization: Mapped["Authorization"] = relationship(back_populates="scans")
