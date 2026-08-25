"""Parser de la salida JSON de WPScan (F8e).

Traduce el reporte de WPScan (core de WordPress + plugins + temas, con sus
vulnerabilidades conocidas cruzadas por versión) a hallazgos normalizados en
español, con CVE y una severidad **representativa** derivada del título de la
vulnerabilidad (WPScan no siempre trae CVSS).

Como en las librerías cliente (F8a/F8b), la versión instalada de un plugin/tema
es autoritativa (no hay backport de distro): el match de versión **confirma** la
exposición. Se reporta `confirmado`.
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
    SEV_MEDIA,
)

# Heurística título → (severidad representativa, CWE). Conservadora: solo eleva
# a alta/crítica ante clases claramente graves; el resto queda en media.
_RULES = [
    (re.compile(r"remote code|rce|code execution|object injection", re.I), SEV_CRITICA, "CWE-94"),
    (re.compile(r"sql injection|sqli", re.I), SEV_CRITICA, "CWE-89"),
    (re.compile(r"authentication bypass|auth bypass|privilege escalation", re.I), SEV_CRITICA, "CWE-287"),
    (re.compile(r"arbitrary file (upload|write)|unrestricted file upload", re.I), SEV_CRITICA, "CWE-434"),
    (re.compile(r"arbitrary file (read|download)|local file inclusion|lfi|path traversal", re.I), SEV_ALTA, "CWE-22"),
    (re.compile(r"ssrf|server.side request", re.I), SEV_ALTA, "CWE-918"),
    (re.compile(r"xml external|xxe", re.I), SEV_ALTA, "CWE-611"),
    (re.compile(r"cross.site scripting|xss", re.I), SEV_MEDIA, "CWE-79"),
    (re.compile(r"cross.site request forgery|csrf", re.I), SEV_MEDIA, "CWE-352"),
    (re.compile(r"information disclosure|sensitive data|disclosure", re.I), SEV_MEDIA, "CWE-200"),
    (re.compile(r"open redirect", re.I), SEV_MEDIA, "CWE-601"),
]


def _sev_cwe(title: str) -> tuple[str, str]:
    for rx, sev, cwe in _RULES:
        if rx.search(title or ""):
            return sev, cwe
    # Vulnerabilidad conocida sin clase clara: media representativa.
    return SEV_MEDIA, "No aplica"


def _cves(refs: dict) -> list[str]:
    out = []
    for c in (refs or {}).get("cve", []) or []:
        c = str(c).strip()
        if not c:
            continue
        out.append(c if c.upper().startswith("CVE-") else f"CVE-{c}")
    return out


def _refs_urls(refs: dict) -> list[str]:
    return [u for u in (refs or {}).get("url", []) or []][:5]


def _emit(kind_es: str, name: str, version: str, vuln: dict, target: str) -> FindingCandidate:
    title = vuln.get("title") or f"{name} {version}"
    sev, cwe = _sev_cwe(title)
    cves = _cves(vuln.get("references") or {})
    fixed = vuln.get("fixed_in")

    etiqueta = f"{kind_es}: {name}" + (f" {version}" if version else "")
    evidencia = f"{etiqueta}. Vulnerabilidad reportada por WPScan: {title}."
    if fixed:
        recomendacion = (
            f"Actualizar {kind_es.lower()} «{name}» a la versión {fixed} o superior. "
            f"En WordPress la versión instalada es autoritativa: el número confirma la exposición.")
    else:
        recomendacion = (
            f"Actualizar {kind_es.lower()} «{name}» a la última versión mantenida o "
            f"reemplazarlo si está sin soporte.")

    return FindingCandidate(
        titulo=f"{kind_es} vulnerable: {name}" + (f" {version}" if version else ""),
        severidad=sev,
        estado=EST_CONFIRMADO,
        herramienta_origen="wpscan",
        sistema_afectado=target,
        evidencia=evidencia,
        cve=", ".join(cves) if cves else "No aplica",
        cwe=cwe,
        recomendacion=recomendacion,
        mas_info=" | ".join(_refs_urls(vuln.get("references") or {})),
        dedup_key=f"wpscan:{name.lower()}:{(cves[0] if cves else title[:40]).lower()}",
    )


def parse(path: str, ctx: Ctx) -> list[FindingCandidate]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict) or "gated" in data or "error" in data:
        return []  # gateado (no WordPress) o WPScan sin salida útil

    target = ctx.target_url or ctx.host or data.get("target_url") or ""
    out: list[FindingCandidate] = []

    # Core de WordPress.
    version = data.get("version") or {}
    wp_num = version.get("number") or ""
    for v in version.get("vulnerabilities") or []:
        out.append(_emit("Núcleo de WordPress", f"WordPress {wp_num}".strip(), "", v, target))

    # Plugins.
    for slug, info in (data.get("plugins") or {}).items():
        ver = ((info or {}).get("version") or {}).get("number") or ""
        for v in (info or {}).get("vulnerabilities") or []:
            out.append(_emit("Plugin", slug, ver, v, target))

    # Temas.
    for slug, info in (data.get("themes") or {}).items():
        ver = ((info or {}).get("version") or {}).get("number") or ""
        for v in (info or {}).get("vulnerabilities") or []:
            out.append(_emit("Tema", slug, ver, v, target))

    return out
