from fastapi import APIRouter

from app.models import AnalysisType
from app.schemas import AnalysisTypeInfo

router = APIRouter(tags=["meta"])


@router.get("/analysis-types", response_model=list[AnalysisTypeInfo])
def analysis_types():
    """Alimenta la pantalla de inicio. BIEC habilitado; el resto, próximamente."""
    return [
        AnalysisTypeInfo(
            id=AnalysisType.biec,
            label="BIEC",
            description="Barrido Inicial de Exposición Crítica. Reconocimiento, "
            "enumeración, descubrimiento de contenido y detección de "
            "vulnerabilidades y configuración, automatizado por etapas.",
            enabled=True,
        ),
        AnalysisTypeInfo(
            id=AnalysisType.bajo_nivel,
            label="Análisis de Bajo Nivel",
            description="Validación manual profunda de los hallazgos del BIEC.",
            enabled=False,
        ),
        AnalysisTypeInfo(
            id=AnalysisType.alto_nivel,
            label="Análisis de Alto Nivel",
            description="Evaluación avanzada y explotación controlada.",
            enabled=False,
        ),
    ]
