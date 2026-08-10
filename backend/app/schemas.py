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


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    analysis_type: AnalysisType
    status: ScanStatus
    created_at: datetime
    project: ProjectRead
    authorization: AuthorizationRead


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
