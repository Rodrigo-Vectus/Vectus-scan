"""whatweb --log-json → tecnologías y fugas (B.4).

- HTTPServer con versión → divulgación de versión (baja). dedup_key común con
  la cabecera Server de curl para consolidar (B.11).
- Librerías JS con versión → info (correlación de CVE en F3b).
- Email[...] → divulgación de correos; se filtran placeholders.
"""
import json
import re

from worker.parsers import SEV_BAJA, SEV_INFO, EST_CONFIRMADO, FindingCandidate, version_review

_PLACEHOLDER_RE = re.compile(
    r"(tu@|you@|your@|example@|user@|email@|nombre@|test@|@example\.|@email\.|@dominio\.|@domain\.)",
    re.IGNORECASE,
)
# Plugin de whatweb → nombre del paquete en npm (para validar CVEs vía OSV, F8).
_LIB_OSV = {
    "jQuery": "jquery",
    "Bootstrap": "bootstrap",
    "Moment.js": "moment",
    "core-js": "core-js",
    "Lodash": "lodash",
    "React": "react",
    "Vue.js": "vue",
    "AngularJS": "angular",
    "Modernizr": "modernizr",
}

# Índice por clave en minúsculas: whatweb reporta el plugin con capitalización
# variable (p. ej. "JQuery" en vez de "jQuery"), así que el match es
# case-insensitive. Valor = (nombre canónico para mostrar, paquete npm).
_LIB_INDEX = {name.lower(): (name, npm) for name, npm in _LIB_OSV.items()}


def _first_version(versions) -> str:
    """Primera versión concreta (x.y[.z]) de la lista, o '' si no hay."""
    for v in versions or []:
        s = str(v).strip()
        if re.match(r"^\d+(\.\d+)+", s):
            return s
    return ""


def _server_key(value: str) -> str:
    # "Apache/2.4.7 (Ubuntu)" → "apache/2.4.7" (para de-dup con curl)
    token = (value or "").split()[0] if value else ""
    return f"server-version:{token.lower()}" if token else "server-version"


def _load(path: str):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception:
        return []
    return data if isinstance(data, list) else [data]


def parse(path: str, ctx) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    for entry in _load(path):
        plugins = entry.get("plugins") or {}
        target = entry.get("target") or ctx.target_url

        server = plugins.get("HTTPServer", {})
        server_vals = server.get("string") or server.get("version") or []
        for val in server_vals:
            if re.search(r"\d", str(val)):  # tiene número de versión
                out.append(
                    FindingCandidate(
                        titulo="Divulgación de versión del servidor web",
                        severidad=SEV_BAJA,
                        estado=EST_CONFIRMADO,
                        herramienta_origen="whatweb",
                        sistema_afectado=target,
                        evidencia=f"HTTPServer: {val}",
                        cwe="CWE-200",
                        recomendacion="Ocultar/normalizar la cabecera Server para no revelar versión exacta.",
                        dedup_key=_server_key(str(val)),
                    )
                )
                prod, _, rest = str(val).partition("/")
                ver = rest.split()[0] if rest.strip() else ""
                if ver:
                    out.append(version_review(prod, ver, "whatweb", target))

        for plugin_name, info in plugins.items():
            entry = _LIB_INDEX.get(plugin_name.lower())
            if not entry or not info:
                continue
            lib, npm_name = entry
            versions = info.get("version") or []
            ver = ", ".join(str(v) for v in versions) if versions else "sin versión"
            exact = _first_version(versions)
            # Si hay versión exacta, se adjunta la pista `pkg` para que el
            # enriquecedor la valide contra OSV (F8a). Sin versión, queda como
            # simple detección (info).
            pkg = ("npm", npm_name, exact) if exact else None
            out.append(
                FindingCandidate(
                    titulo=f"Librería front-end detectada: {lib} ({ver})",
                    severidad=SEV_INFO,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="whatweb",
                    sistema_afectado=target,
                    evidencia=f"{lib}: {ver}",
                    recomendacion="Verificar que la versión no tenga CVE conocidos (validación en fase de bajo nivel).",
                    dedup_key=f"lib:{lib.lower()}",
                    pkg=pkg,
                )
            )

        email = plugins.get("Email", {})
        emails = email.get("string") or []
        reales = [e for e in emails if not _PLACEHOLDER_RE.search(str(e))]
        if reales:
            out.append(
                FindingCandidate(
                    titulo="Divulgación de direcciones de correo",
                    severidad=SEV_BAJA,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="whatweb",
                    sistema_afectado=target,
                    evidencia="Correos servidos: " + ", ".join(sorted(set(map(str, reales)))),
                    cwe="CWE-200",
                    recomendacion="Evitar exponer correos en el HTML; usar formularios o ofuscación.",
                    dedup_key="email-disclosure",
                    ocurrencias=len(set(reales)),
                )
            )
    return out
