from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.models import AnalysisType, ScanStatus


# ─── Entrada ────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    """Payload para crear un scan. Crea proyecto + autorización + scan.

    Reglas del principio rector, validadas en el servidor (no solo en el
    front): `authorized` debe ser True, y en la Fase 1 solo se acepta BIEC.
    """

    project_name: str
    client: str | None = None
    target: str
    responsible_user: str
    analysis_type: AnalysisType = AnalysisType.biec
    authorized: bool
    note: str | None = None
    folder_id: int | None = None  # F10: carpeta opcional al crear

    @field_validator("project_name", "target", "responsible_user")
    @classmethod
    def not_blank(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("no puede estar vacío")
        return v

    @field_validator("target")
    @classmethod
    def target_looks_like_url_or_host(cls, v: str) -> str:
        v = v.strip()
        # Validación laxa: aceptamos http(s)://host o host pelado.
        # La normalización fina del target vive en el motor (Fase 2).
        if " " in v or "." not in v:
            raise ValueError("target inválido: debe ser una URL o host (ej. https://ejemplo.com)")
        return v

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError(
                "No se puede crear un scan sin autorización confirmada para el objetivo."
            )
        return v

    @field_validator("analysis_type")
    @classmethod
    def only_biec_for_now(cls, v: AnalysisType) -> AnalysisType:
        if v != AnalysisType.biec:
            raise ValueError(
                "Solo el BIEC está disponible por ahora. "
                "Los análisis de bajo y alto nivel llegan próximamente."
            )
        return v


# ─── Salida ─────────────────────────────────────────────────────────

class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    client: str | None
    created_at: datetime


class AuthorizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    responsible_user: str
    authorized: bool
    note: str | None
    created_at: datetime


class FolderCreate(BaseModel):
    """Alta/edición de carpeta. El nombre es la identidad: único y no vacío."""

    nombre: str
    descripcion: str | None = None

    @field_validator("nombre")
    @classmethod
    def nombre_valido(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("El nombre de la carpeta no puede estar vacío.")
        if len(v) > 120:
            raise ValueError("El nombre no puede superar los 120 caracteres.")
        return v


class FolderUpdate(BaseModel):
    nombre: str | None = None
    descripcion: str | None = None

    @field_validator("nombre")
    @classmethod
    def nombre_valido(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("El nombre de la carpeta no puede estar vacío.")
        return v


class FolderRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nombre: str
    descripcion: str | None = None
    created_at: datetime
    scans: int = 0  # cantidad de análisis dentro (lo calcula el router)


class ScanMove(BaseModel):
    """Mover un scan a una carpeta. `folder_id=None` lo saca de toda carpeta."""

    folder_id: int | None = None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    cliente: str | None = None
    folder_id: int | None = None
    analysis_type: AnalysisType
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None = None
    project: ProjectRead
    authorization: AuthorizationRead


class ScanHistoryRow(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    cliente: str | None = None
    folder_id: int | None = None
    folder_nombre: str | None = None
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None = None
    critica: int = 0
    alta: int = 0
    media: int = 0
    baja: int = 0
    vulnerabilidades: int = 0
    a_validar: int = 0


class DashboardResponse(BaseModel):
    total_scans: int
    completados: int
    en_curso: int
    con_error: int
    vuln_critica: int = 0
    vuln_alta: int = 0
    vuln_media: int = 0
    vuln_baja: int = 0
    vuln_total: int = 0
    scans: list[ScanHistoryRow]


class AnalysisTypeInfo(BaseModel):
    id: AnalysisType
    label: str
    description: str
    enabled: bool


# ─── Progreso de ejecución (F2) ─────────────────────────────────────

class ToolRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tool: str
    status: str
    exit_code: int | None
    started_at: datetime | None
    finished_at: datetime | None


class ScanStageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    order: int
    key: str
    label: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    tool_runs: list[ToolRunRead]


class ScanProgress(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: ScanStatus
    estimated_seconds: int | None
    started_at: datetime | None
    finished_at: datetime | None
    stages: list[ScanStageRead]


# ─── Hallazgos (F3) ─────────────────────────────────────────────────

class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    titulo: str
    severidad: str
    cvss: float | None
    cvss_vector: str | None
    sistema_afectado: str | None
    evidencia: str | None
    herramienta_origen: str
    cve: str
    cwe: str | None
    recomendacion: str | None
    mas_info: str | None
    estado: str
    ocurrencias: int


class SeveritySummary(BaseModel):
    critica: int = 0
    alta: int = 0
    media: int = 0
    baja: int = 0
    info: int = 0
    total: int = 0
    positivos: int = 0
    a_validar: int = 0


class FindingsResponse(BaseModel):
    scan_id: int
    status: ScanStatus
    summary: SeveritySummary
    findings: list[FindingRead]


# ─── Autenticación / usuarios / auditoría (F7) ──────────────────────

from app.models import ROLES  # noqa: E402


def _norm_email(v: str) -> str:
    v = (v or "").strip().lower()
    if "@" not in v or "." not in v.split("@")[-1]:
        raise ValueError("email inválido")
    return v


class RequestCodeIn(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return _norm_email(v)


class VerifyCodeIn(BaseModel):
    email: str
    code: str

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return _norm_email(v)

    @field_validator("code")
    @classmethod
    def _code(cls, v: str) -> str:
        v = (v or "").strip()
        if not (v.isdigit() and len(v) == 6):
            raise ValueError("el código debe tener 6 dígitos")
        return v


class MessageResponse(BaseModel):
    message: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    nombre: str
    rol: str
    activo: bool
    created_at: datetime


class UserCreate(BaseModel):
    email: str
    nombre: str
    rol: str = "analista"

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return _norm_email(v)

    @field_validator("nombre")
    @classmethod
    def _nombre(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("el nombre no puede estar vacío")
        return v

    @field_validator("rol")
    @classmethod
    def _rol(cls, v: str) -> str:
        if v not in ROLES:
            raise ValueError(f"rol inválido: debe ser uno de {ROLES}")
        return v


class UserUpdate(BaseModel):
    """Todos opcionales: se actualiza solo lo que venga."""

    nombre: str | None = None
    rol: str | None = None
    activo: bool | None = None

    @field_validator("nombre")
    @classmethod
    def _nombre(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("el nombre no puede estar vacío")
        return v

    @field_validator("rol")
    @classmethod
    def _rol(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v not in ROLES:
            raise ValueError(f"rol inválido: debe ser uno de {ROLES}")
        return v


class AuthEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    kind: str
    at: datetime
    ip: str | None
    detail: str | None
