"""Parsers de salidas crudas → hallazgos normalizados (Parte B del anexo).

Cada parser es una función pura `parse(paths, ctx) -> list[FindingCandidate]`
que no toca la base de datos ni ejecuta nada: recibe rutas de archivos raw y
un contexto, y devuelve candidatos. Eso los hace testeables con fixtures.
La consolidación/de-dup y la escritura a la DB están en worker/consolidate.py.
"""
from dataclasses import dataclass, field

# ── Severidad (B.1/B.2) ──
SEV_CRITICA = "critica"
SEV_ALTA = "alta"
SEV_MEDIA = "media"
SEV_BAJA = "baja"
SEV_INFO = "info"
SEV_ORDER = {SEV_CRITICA: 0, SEV_ALTA: 1, SEV_MEDIA: 2, SEV_BAJA: 3, SEV_INFO: 4}

# ── Estado (B.1) ──
EST_CONFIRMADO = "confirmado"
EST_A_VALIDAR = "a_validar"
EST_FALSO_POSITIVO = "falso_positivo"
EST_POSITIVO = "positivo"


@dataclass
class Ctx:
    """Contexto del scan que los parsers pueden necesitar."""
    target_url: str = ""
    host: str = ""


@dataclass
class FindingCandidate:
    titulo: str
    severidad: str
    herramienta_origen: str
    estado: str = EST_CONFIRMADO
    cvss: float | None = None
    cvss_vector: str | None = None
    sistema_afectado: str | None = None
    evidencia: str | None = None
    cve: str = "No aplica"
    cwe: str | None = None
    recomendacion: str | None = None
    mas_info: str | None = None
    ocurrencias: int = 1
    # Clave semántica de de-dup (B.11). Si dos candidatos comparten dedup_key,
    # se fusionan. Por defecto se arma única por (tool, titulo, sistema).
    dedup_key: str = ""

    def key(self) -> str:
        if self.dedup_key:
            return self.dedup_key
        return f"{self.herramienta_origen}|{self.titulo}|{self.sistema_afectado or ''}"


def nuclei_severity(raw: str) -> str:
    """Mapea info.severity de nuclei a severidad interna (B.2)."""
    return {
        "critical": SEV_CRITICA,
        "high": SEV_ALTA,
        "medium": SEV_MEDIA,
        "low": SEV_BAJA,
        "info": SEV_INFO,
        "unknown": SEV_INFO,
    }.get((raw or "").strip().lower(), SEV_INFO)


def cvss_to_severity(score: float) -> str:
    """Rangos CVSS → severidad (B.2)."""
    if score >= 9.0:
        return SEV_CRITICA
    if score >= 7.0:
        return SEV_ALTA
    if score >= 4.0:
        return SEV_MEDIA
    if score > 0.0:
        return SEV_BAJA
    return SEV_INFO
