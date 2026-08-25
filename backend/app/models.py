import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    Float,
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


class Folder(Base):
    """Carpeta para agrupar scans (F10). Nombre único, sin anidamiento.

    Los scans sin carpeta son válidos (`folder_id` nullable): existían antes
    de esta migración y siguen apareciendo bajo "Sin carpeta". Una carpeta
    con scans no se puede borrar: el borrado no debe arrastrar análisis por
    accidente."""

    __tablename__ = "folders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    nombre: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    descripcion: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scans: Mapped[list["Scan"]] = relationship(back_populates="folder")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    cliente: Mapped[str | None] = mapped_column(String(200), nullable=True)
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

    # F10: carpeta opcional. Sin carpeta = scans previos a la migración y los
    # que se creen sin elegir una. ondelete no hace falta: el endpoint impide
    # borrar carpetas que tengan scans.
    folder_id: Mapped[int | None] = mapped_column(
        ForeignKey("folders.id"), nullable=True, index=True
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
    folder: Mapped["Folder | None"] = relationship(back_populates="scans")
    authorization: Mapped["Authorization"] = relationship(back_populates="scans")
    stages: Mapped[list["ScanStage"]] = relationship(
        back_populates="scan",
        order_by="ScanStage.order",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
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


# ─── Hallazgos (F3) ─────────────────────────────────────────────────
# Severidad y estado como VARCHAR + constantes (sin enum de PG), igual que
# los estados de etapa. Valores canónicos del anexo (B.1/B.2).

SEV_CRITICA = "critica"
SEV_ALTA = "alta"
SEV_MEDIA = "media"
SEV_BAJA = "baja"
SEV_INFO = "info"
SEVERITIES = [SEV_CRITICA, SEV_ALTA, SEV_MEDIA, SEV_BAJA, SEV_INFO]

EST_CONFIRMADO = "confirmado"
EST_A_VALIDAR = "a_validar"
EST_FALSO_POSITIVO = "falso_positivo"
EST_POSITIVO = "positivo"  # buena postura


class Finding(Base):
    """Hallazgo consolidado y normalizado (B.1). El worker lo escribe a partir
    del raw; el backend solo lo lee para la API/informe."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"), nullable=False, index=True
    )

    titulo: Mapped[str] = mapped_column(String(300), nullable=False)
    severidad: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    sistema_afectado: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidencia: Mapped[str | None] = mapped_column(Text, nullable=True)
    herramienta_origen: Mapped[str] = mapped_column(String(120), nullable=False)
    cve: Mapped[str] = mapped_column(String(200), nullable=False, default="No aplica")
    cwe: Mapped[str | None] = mapped_column(String(120), nullable=True)
    recomendacion: Mapped[str | None] = mapped_column(Text, nullable=True)
    mas_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    estado: Mapped[str] = mapped_column(String(20), nullable=False)
    ocurrencias: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Clave semántica para de-duplicar entre herramientas (B.11).
    dedup_key: Mapped[str] = mapped_column(String(300), nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="findings")


# ─── Autenticación / usuarios / auditoría (F7) ──────────────────────
# Roles y tipos de evento como VARCHAR + constantes (mismo criterio que
# severidad/estado: sin enum de PG, más simple de migrar/extender).

ROL_ADMIN = "administrador"
ROL_ANALISTA = "analista"
ROLES = [ROL_ADMIN, ROL_ANALISTA]

# Tipos de evento de auditoría. La vista de accesos (login/logout) sale
# de filtrar por AUTH_LOGIN / AUTH_LOGOUT.
AUTH_CODE_SENT = "code_sent"
AUTH_LOGIN = "login"
AUTH_LOGOUT = "logout"
AUTH_CODE_FAILED = "code_failed"
AUTH_LOGIN_FAILED = "login_failed"


class User(Base):
    """Usuario de la plataforma. El OTP solo se envía a usuarios que existan
    aquí y estén `activo`. Nunca se borra un usuario: se desactiva, para
    preservar la auditoría (AuthEvent referencia el email)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(
        String(320), nullable=False, unique=True, index=True
    )
    nombre: Mapped[str] = mapped_column(String(200), nullable=False)
    rol: Mapped[str] = mapped_column(String(20), nullable=False, default=ROL_ANALISTA)
    activo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class OtpCode(Base):
    """Código OTP de un solo uso. Se guarda HASHEADO (HMAC con pepper),
    nunca en claro. `used_at` marca el consumo; `attempts` limita los
    intentos fallidos; `expires_at` la ventana de 10 minutos."""

    __tablename__ = "otp_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuthSession(Base):
    """Sesión por cookie. El token viaja SOLO en la cookie httpOnly; en la
    DB se guarda su hash (un dump de la tabla no permite secuestrar sesiones).
    Sesión deslizante: `expires_at` se corre cuando pasó más de la mitad de
    su vida (se renueva en `deps.get_current_user`)."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AuthEvent(Base):
    """Bitácora de auditoría de autenticación. Fuente de la vista de accesos
    (login/logout por usuario y fecha) y del rastro de códigos enviados/
    fallidos."""

    __tablename__ = "auth_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(300), nullable=True)
