"""Catálogo canónico de las 5 etapas del BIEC.

El backend usa esto para crear las filas de `ScanStage` al lanzar y para
estimar la duración. El worker referencia las mismas `key` al ejecutar
(hay un test que verifica que ambos lados coincidan).
"""

STAGES = [
    {"order": 1, "key": "reconocimiento", "label": "Reconocimiento", "est": 60},
    {"order": 2, "key": "enumeracion", "label": "Enumeración", "est": 40},
    {"order": 3, "key": "descubrimiento", "label": "Descubrimiento de contenido", "est": 120},
    {"order": 4, "key": "vulnerabilidades", "label": "Escaneo de vulnerabilidades", "est": 240},
    {"order": 5, "key": "configuracion", "label": "Configuración de seguridad", "est": 40},
]

STAGE_KEYS = [s["key"] for s in STAGES]
ESTIMATED_TOTAL_SECONDS = sum(s["est"] for s in STAGES)
