"""ffuf -of json → descubrimiento de contenido (B.7).

Interpretación por patrón, no ruta por ruta:
- Namespace respondiendo 401 con tamaño idéntico → positivo (middleware de auth).
- 403 masivo a rutas inexistentes → positivo: hay WAF/filtrado que corta el fuzzing.
- 200 a muchísimas rutas (catch-all/SPA/soft-404) → NO se lista ruta por ruta;
  se colapsa en una sola observación `a_validar` (el 200 no confirma existencia).
- En un sitio normal (pocos 200): 200 en rutas sensibles → alta; /health,
  /status, /debug → a_validar; resto → info.
"""
import json

from worker.parsers import (
    SEV_ALTA,
    SEV_BAJA,
    SEV_INFO,
    EST_CONFIRMADO,
    EST_A_VALIDAR,
    EST_POSITIVO,
    FindingCandidate,
)

_SENSIBLES = (".env", ".git", ".svn", "backup", "config", "id_rsa", ".htpasswd",
              "wp-config", ".sql", "dump", "secret", ".bak")
_REVISAR = ("health", "status", "debug", "actuator", "metrics", "info", "trace")

# Si hay al menos este número de 200, se asume catch-all (no se lista cada ruta).
CATCHALL_200 = 20
# 403 a tantas rutas se interpreta como filtrado/WAF.
MASS_403 = 20


def _fuzz(result: dict) -> str:
    inp = result.get("input") or {}
    return str(inp.get("FUZZ") or result.get("url") or "")


def _is_sensitive(f: str) -> bool:
    return any(s in f.lower() for s in _SENSIBLES)


def _is_revisar(f: str) -> bool:
    return any(s in f.lower() for s in _REVISAR)


def parse(path: str, ctx) -> list[FindingCandidate]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except Exception:
        return []

    results = data.get("results") or []
    out: list[FindingCandidate] = []
    r200 = [r for r in results if r.get("status") == 200]
    r401 = [r for r in results if r.get("status") == 401]
    r403 = [r for r in results if r.get("status") == 403]

    # 401 uniforme → middleware de auth (positivo).
    if len(r401) >= 5 and len({r.get("length") for r in r401}) == 1:
        out.append(
            FindingCandidate(
                titulo="Namespace protegido por middleware de autenticación",
                severidad=SEV_BAJA,
                estado=EST_POSITIVO,
                herramienta_origen="ffuf",
                sistema_afectado=ctx.target_url,
                evidencia=f"{len(r401)} rutas responden 401 con tamaño idéntico.",
                recomendacion="Buena postura: la autenticación intercepta antes de rutear.",
                dedup_key="ffuf:401-namespace",
            )
        )

    # 403 masivo → filtrado/WAF (buena postura).
    if len(r403) >= MASS_403:
        out.append(
            FindingCandidate(
                titulo="Filtrado/WAF activo ante el descubrimiento de contenido",
                severidad=SEV_INFO,
                estado=EST_POSITIVO,
                herramienta_origen="ffuf",
                sistema_afectado=ctx.target_url,
                evidencia=f"{len(r403)} rutas responden 403 (probable WAF/filtrado).",
                recomendacion="Buena postura: el filtrado corta el fuzzing de rutas.",
                dedup_key="ffuf:403-waf",
            )
        )

    catchall = len(r200) >= CATCHALL_200

    if catchall:
        out.append(
            FindingCandidate(
                titulo="Respuestas 200 indiscriminadas (posible catch-all/SPA)",
                severidad=SEV_INFO,
                estado=EST_A_VALIDAR,
                herramienta_origen="ffuf",
                sistema_afectado=ctx.target_url,
                evidencia=(
                    f"{len(r200)} rutas distintas responden 200; el servidor parece "
                    "devolver contenido para casi cualquier ruta (SPA/soft-404). "
                    "El descubrimiento por fuerza bruta no es concluyente."
                ),
                recomendacion="Validar manualmente; un 200 no confirma que el recurso exista.",
                dedup_key="ffuf:catch-all",
            )
        )
        # aun en catch-all, marcar rutas sensibles como a_validar (200 dudoso, no confirmado).
        for r in r200:
            f = _fuzz(r)
            if _is_sensitive(f):
                out.append(
                    FindingCandidate(
                        titulo=f"Ruta sensible /{f} responde 200 (dudoso por catch-all)",
                        severidad=SEV_BAJA,
                        estado=EST_A_VALIDAR,
                        herramienta_origen="ffuf",
                        sistema_afectado=r.get("url") or f"{ctx.target_url}/{f}",
                        evidencia=f"HTTP 200 en /{f}; el sitio responde 200 a casi todo. Verificar.",
                        cwe="CWE-538",
                        recomendacion="Verificar manualmente si el archivo existe realmente.",
                        dedup_key=f"ffuf:sensible:{f.lower()}",
                    )
                )
        return out

    # Sitio normal (pocos 200): interpretación por ruta.
    for r in r200:
        fuzz = _fuzz(r)
        low = fuzz.lower()
        url = r.get("url") or f"{ctx.target_url}/{fuzz}"
        if _is_sensitive(fuzz):
            out.append(
                FindingCandidate(
                    titulo=f"Archivo/directorio sensible accesible: /{fuzz}",
                    severidad=SEV_ALTA,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="ffuf",
                    sistema_afectado=url,
                    evidencia=f"HTTP 200 en /{fuzz}",
                    cwe="CWE-538",
                    recomendacion="Bloquear el acceso público; mover fuera del webroot y revisar exposición.",
                    dedup_key=f"ffuf:sensible:{low}",
                )
            )
        elif _is_revisar(fuzz):
            out.append(
                FindingCandidate(
                    titulo=f"Endpoint de diagnóstico expuesto: /{fuzz}",
                    severidad=SEV_BAJA,
                    estado=EST_A_VALIDAR,
                    herramienta_origen="ffuf",
                    sistema_afectado=url,
                    evidencia=f"HTTP 200 en /{fuzz}",
                    cwe="CWE-200",
                    recomendacion="Revisar el cuerpo: puede filtrar info interna. Restringir la respuesta.",
                    dedup_key=f"ffuf:revisar:{low}",
                )
            )
        else:
            out.append(
                FindingCandidate(
                    titulo=f"Ruta encontrada: /{fuzz}",
                    severidad=SEV_INFO,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="ffuf",
                    sistema_afectado=url,
                    evidencia=f"HTTP 200 en /{fuzz}",
                    dedup_key=f"ffuf:200:{low}",
                )
            )
    return out
