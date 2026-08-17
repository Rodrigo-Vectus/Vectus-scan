"""curl (headers) → análisis de configuración (B.9).

Parsea las cabeceras de la respuesta final (tras redirecciones). Ausencia de
cabeceras de seguridad → hallazgos baja; presencia completa → positivo.
Server con versión, Set-Cookie sin flags y Content-Encoding (BREACH) también.
"""
from worker.parsers import (
    SEV_BAJA,
    SEV_INFO,
    EST_CONFIRMADO,
    EST_POSITIVO,
    FindingCandidate,
)

# (nombre-header, título, cwe, recomendación)
_SEC_HEADERS = [
    ("content-security-policy", "Content-Security-Policy (CSP) ausente", "CWE-1021",
     "Definir una CSP restrictiva para mitigar XSS e inyección de contenido."),
    ("strict-transport-security", "HSTS (Strict-Transport-Security) ausente", "CWE-319",
     "Agregar HSTS para forzar HTTPS y evitar downgrade."),
    ("x-frame-options", "X-Frame-Options ausente", "CWE-1021",
     "Agregar X-Frame-Options: DENY/SAMEORIGIN para prevenir clickjacking."),
    ("x-content-type-options", "X-Content-Type-Options ausente", "CWE-693",
     "Agregar X-Content-Type-Options: nosniff."),
    ("referrer-policy", "Referrer-Policy ausente", "CWE-200",
     "Definir Referrer-Policy para no filtrar URLs por el header Referer."),
    ("permissions-policy", "Permissions-Policy ausente", "CWE-693",
     "Definir Permissions-Policy para restringir APIs del navegador."),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy (COOP) ausente", "CWE-693",
     "Agregar COOP para aislar el contexto de navegación."),
]


def _parse_headers(path: str) -> dict:
    """Devuelve las cabeceras de la ÚLTIMA respuesta (dict lower→valor) y la
    lista cruda de Set-Cookie."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except Exception:
        return {}, []
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            headers = {}  # nueva respuesta: reiniciar (quedarse con la final)
            cookies = []
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "set-cookie":
            cookies.append(value)
        elif name:
            headers[name] = value
    return headers, cookies


def parse(path: str, ctx) -> list[FindingCandidate]:
    headers, cookies = _parse_headers(path)
    if not headers:
        return []  # sin respuesta capturada: no inventamos hallazgos

    out: list[FindingCandidate] = []
    sistema = ctx.target_url
    faltantes = 0

    for name, titulo, cwe, reco in _SEC_HEADERS:
        if name not in headers:
            faltantes += 1
            out.append(
                FindingCandidate(
                    titulo=titulo,
                    severidad=SEV_BAJA,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="curl",
                    sistema_afectado=sistema,
                    evidencia=f"La cabecera '{name}' no está presente en la respuesta.",
                    cwe=cwe,
                    recomendacion=reco,
                    dedup_key=f"header-missing:{name}",
                )
            )

    csp = headers.get("content-security-policy")
    if csp and "'unsafe-inline'" in csp:
        out.append(
            FindingCandidate(
                titulo="CSP permisiva ('unsafe-inline')",
                severidad=SEV_BAJA,
                estado=EST_CONFIRMADO,
                herramienta_origen="curl",
                sistema_afectado=sistema,
                evidencia=f"Content-Security-Policy: {csp[:200]}",
                cwe="CWE-1021",
                recomendacion="Evitar 'unsafe-inline'; usar nonces/hashes para scripts y estilos.",
                dedup_key="csp:unsafe-inline",
            )
        )

    if faltantes == 0:
        out.append(
            FindingCandidate(
                titulo="Cabeceras de seguridad completas",
                severidad=SEV_INFO,
                estado=EST_POSITIVO,
                herramienta_origen="curl",
                sistema_afectado=sistema,
                evidencia="Todas las cabeceras de seguridad revisadas están presentes.",
                recomendacion="Buena postura: mantener la configuración de cabeceras.",
                dedup_key="headers:completas",
            )
        )

    server = headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        out.append(
            FindingCandidate(
                titulo="Divulgación de versión del servidor web",
                severidad=SEV_BAJA,
                estado=EST_CONFIRMADO,
                herramienta_origen="curl",
                sistema_afectado=sistema,
                evidencia=f"Server: {server}",
                cwe="CWE-200",
                recomendacion="Ocultar/normalizar la cabecera Server.",
                dedup_key=f"server-version:{server.split()[0].lower()}",
            )
        )

    for cookie in cookies:
        low = cookie.lower()
        faltan = [f for f in ("secure", "httponly", "samesite") if f not in low]
        if faltan:
            nombre = cookie.split("=", 1)[0]
            out.append(
                FindingCandidate(
                    titulo=f"Cookie sin flags de seguridad: {nombre}",
                    severidad=SEV_BAJA,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="curl",
                    sistema_afectado=sistema,
                    evidencia=f"Set-Cookie: {cookie[:150]} (faltan: {', '.join(faltan)})",
                    cwe="CWE-614",
                    recomendacion="Marcar cookies con Secure, HttpOnly y SameSite según corresponda.",
                    dedup_key=f"cookie-flags:{nombre.lower()}",
                )
            )

    enc = headers.get("content-encoding", "").lower()
    if enc in ("gzip", "deflate", "br"):
        out.append(
            FindingCandidate(
                titulo="Compresión HTTP habilitada (susceptibilidad teórica a BREACH)",
                severidad=SEV_INFO,
                estado=EST_CONFIRMADO,
                herramienta_origen="curl",
                sistema_afectado=sistema,
                evidencia=f"Content-Encoding: {enc}",
                cve="CVE-2013-3587",
                recomendacion="Riesgo teórico; mitigar si se sirven secretos reflejados junto a input del usuario.",
                dedup_key="breach",
            )
        )
    return out
