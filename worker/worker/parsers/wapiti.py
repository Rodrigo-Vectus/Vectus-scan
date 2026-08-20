"""Parser de la salida JSON de wapiti (F8c) con localización al español (F8d).

wapiti hace detección activa NO intrusiva (SQLi, XSS, inyección de comandos,
LFI/traversal, SSRF, XXE, etc.): envía payloads de prueba y observa la
respuesta para *detectar*, sin explotar (línea Nessus/Greenbone).

Los textos de wapiti vienen en inglés. Acá se traduce el **título** y la
**evidencia** al español (para la web) y se asigna un **slug** estable en el
`dedup_key` (`wapiti:<slug>:<path>:<param>`) que el catálogo del informe
(`report_catalog.tipo_de`) mapea a una ficha en español. Así todo el hallazgo
—web e informe— queda en español y con estilo consistente.
"""
import json
import re

from worker.parsers import (
    Ctx,
    EST_CONFIRMADO,
    FindingCandidate,
    SEV_ALTA,
    SEV_BAJA,
    SEV_CRITICA,
    SEV_INFO,
    SEV_MEDIA,
)

# level de wapiti → severidad interna (vulnerability.py: 4=crit .. 0=info).
_LEVEL_SEV = {4: SEV_CRITICA, 3: SEV_ALTA, 2: SEV_MEDIA, 1: SEV_BAJA, 0: SEV_INFO}

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

# Categoría de wapiti (inglés) → (nombre en español, slug para catálogo/dedup).
# El slug agrupa variantes (reflejado/almacenado comparten ficha cuando aplica).
_CATEGORY_ES = {
    "SQL Injection": ("Inyección SQL", "sqli"),
    "Blind SQL Injection": ("Inyección SQL a ciegas", "sqli"),
    "Command execution": ("Ejecución de comandos", "exec"),
    "Path Traversal": ("Path Traversal (recorrido de directorios)", "path-traversal"),
    "LDAP Injection": ("Inyección LDAP", "ldap"),
    "Cross Site Scripting": ("Cross-Site Scripting (XSS) reflejado", "xss"),
    "Reflected Cross Site Scripting": ("Cross-Site Scripting (XSS) reflejado", "xss"),
    "Stored Cross Site Scripting": ("Cross-Site Scripting (XSS) almacenado", "xss-stored"),
    "CRLF Injection": ("Inyección CRLF", "crlf"),
    "Server Side Request Forgery": ("SSRF (falsificación de petición del lado del servidor)", "ssrf"),
    "XML External Entity": ("Inyección de entidad externa XML (XXE)", "xxe"),
    "Open Redirect": ("Redirección abierta", "open-redirect"),
    "Inconsistent Redirection": ("Redirección inconsistente", "open-redirect"),
    "HTML Injection": ("Inyección de HTML", "html-injection"),
    "Stored HTML Injection": ("Inyección de HTML almacenada", "html-injection"),
    "Unrestricted File Upload": ("Carga de archivos sin restricciones", "file-upload"),
    "Htaccess Bypass": ("Elusión de restricciones .htaccess", "htaccess"),
    "Backup file": ("Archivo de respaldo accesible", "backup"),
    "Potentially dangerous file": ("Archivo potencialmente peligroso", "dangerous-file"),
    "Log4Shell": ("Log4Shell (CVE-2021-44228)", "log4shell"),
    "Spring4Shell": ("Spring4Shell", "spring4shell"),
    "Stack Trace Disclosure": ("Divulgación de stack trace", "stack-trace"),
    "Information Disclosure - Full Path": ("Divulgación de ruta absoluta", "full-path"),
    "HTTP Methods": ("Métodos HTTP peligrosos habilitados", "http-methods"),
}

# Módulo de wapiti → texto en español (para la evidencia).
_MODULE_ES = {
    "sql": "inyección SQL", "xss": "XSS", "permanentxss": "XSS almacenado",
    "exec": "ejecución de comandos", "file": "inclusión/recorrido de archivos",
    "crlf": "inyección CRLF", "ssrf": "SSRF", "xxe": "XXE", "ldap": "inyección LDAP",
    "redirect": "redirección abierta", "htaccess": "elusión de .htaccess",
    "backup": "archivos de respaldo", "upload": "carga de archivos",
    "methods": "métodos HTTP", "log4shell": "Log4Shell", "spring4shell": "Spring4Shell",
    "shellshock": "ShellShock",
}


def _localize(category: str) -> tuple[str, str]:
    """(nombre_es, slug) para una categoría; fallback razonable si no está."""
    if category in _CATEGORY_ES:
        return _CATEGORY_ES[category]
    slug = re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-") or "otro"
    return category, slug  # nombre inglés como último recurso


def _cwe(classification: dict) -> str | None:
    for label in (classification.get("ref") or {}):
        m = _CWE_RE.search(label)
        if m:
            return m.group(0).upper()
    return None


def parse(path: str, ctx: Ctx) -> list[FindingCandidate]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []

    vulns = data.get("vulnerabilities") or {}
    classifications = data.get("classifications") or {}
    target = ctx.target_url or ctx.host or ""
    out: list[FindingCandidate] = []

    for category, items in vulns.items():
        if not items:
            continue
        nombre_es, slug = _localize(category)
        cwe = _cwe(classifications.get(category, {}))

        for it in items:
            level = it.get("level", 0)
            sev = _LEVEL_SEV.get(level, SEV_INFO)
            param = it.get("parameter") or ""
            path_ = it.get("path") or "/"
            method = it.get("method") or "GET"
            module = it.get("module") or ""

            titulo = nombre_es + (f" (parámetro '{param}')" if param else "")

            mod_txt = _MODULE_ES.get(module, module)
            evidencia = (
                f"Detectado por wapiti mediante {mod_txt} en {method} {path_}"
                + (f", parámetro '{param}'." if param else ".")
            )
            http_req = it.get("http_request") or ""
            if http_req:
                evidencia += f"\nSolicitud de prueba:\n{http_req[:400]}"

            out.append(
                FindingCandidate(
                    titulo=titulo,
                    severidad=sev,
                    estado=EST_CONFIRMADO,  # wapiti confirma probando activamente
                    herramienta_origen="wapiti",
                    sistema_afectado=f"{target}{path_}" if path_ != "/" else target,
                    evidencia=evidencia,
                    cwe=cwe or "No aplica",
                    # La recomendación definitiva la aporta la ficha del catálogo
                    # (report_catalog) en el informe; acá va un texto en español
                    # por si el hallazgo se ve sin ficha.
                    recomendacion=(
                        "Remediar la vulnerabilidad validando y saneando la entrada "
                        "del usuario en el parámetro afectado (ver ficha del informe)."
                    ),
                    mas_info="",
                    dedup_key=f"wapiti:{slug}:{path_}:{param}",
                )
            )
    return out
