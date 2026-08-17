"""ffuf -of json → descubrimiento de contenido (B.7).

Interpretación por patrón, no ruta por ruta:
- Namespace respondiendo 401 con tamaño idéntico (muchas rutas) → positivo:
  hay middleware de auth; no es fuga de endpoints.
- 200 en rutas sensibles (.env, .git, backup, config…) → hallazgo alto.
- 200 en /health, /status, /debug → a_validar (revisar cuerpo en F3b/B.9).
- Resto de 200 → info (ruta encontrada).
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


def _fuzz(result: dict) -> str:
    inp = result.get("input") or {}
    return str(inp.get("FUZZ") or result.get("url") or "")


def parse(path: str, ctx) -> list[FindingCandidate]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception:
        return []

    results = data.get("results") or []
    out: list[FindingCandidate] = []

    # Patrón 401 uniforme → middleware de auth (positivo).
    r401 = [r for r in results if r.get("status") == 401]
    if len(r401) >= 5 and len({r.get("length") for r in r401}) == 1:
        out.append(
            FindingCandidate(
                titulo="Namespace protegido por middleware de autenticación",
                severidad=SEV_BAJA,
                estado=EST_POSITIVO,
                herramienta_origen="ffuf",
                sistema_afectado=ctx.target_url,
                evidencia=f"{len(r401)} rutas responden 401 con tamaño idéntico "
                          f"({next(iter({r.get('length') for r in r401}))} bytes).",
                recomendacion="Buena postura: la autenticación intercepta antes de rutear; no hay fuga de endpoints.",
                dedup_key="ffuf:401-namespace",
            )
        )

    for r in results:
        if r.get("status") != 200:
            continue
        fuzz = _fuzz(r)
        low = fuzz.lower()
        url = r.get("url") or f"{ctx.target_url}/{fuzz}"

        if any(s in low for s in _SENSIBLES):
            out.append(
                FindingCandidate(
                    titulo=f"Archivo/directorio sensible accesible: /{fuzz}",
                    severidad=SEV_ALTA,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="ffuf",
                    sistema_afectado=url,
                    evidencia=f"HTTP 200 en /{fuzz}",
                    cwe="CWE-538",
                    recomendacion="Bloquear el acceso público; mover fuera del webroot y revisar si hubo exposición.",
                    dedup_key=f"ffuf:sensible:{low}",
                )
            )
        elif any(s in low for s in _REVISAR):
            out.append(
                FindingCandidate(
                    titulo=f"Endpoint de diagnóstico expuesto: /{fuzz}",
                    severidad=SEV_BAJA,
                    estado=EST_A_VALIDAR,
                    herramienta_origen="ffuf",
                    sistema_afectado=url,
                    evidencia=f"HTTP 200 en /{fuzz}",
                    cwe="CWE-200",
                    recomendacion="Revisar el cuerpo: puede filtrar info interna. Restringir o minimizar la respuesta.",
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
