"""nikto -o nikto.txt → servidor web (B.10).

nikto es ruidoso: sus ítems entran como `a_validar` (baja/info). Los ítems de
"cabecera X no seteada" se de-duplican contra curl usando la misma dedup_key
`header-missing:<name>` (el contraste fino header-vs-ruta-real es F3b).
Las líneas informativas (Server, Target, tiempos, resúmenes) se descartan.
"""
import re

from worker.parsers import (
    SEV_BAJA,
    SEV_INFO,
    EST_A_VALIDAR,
    FindingCandidate,
)

# Líneas que NO son hallazgos.
_SKIP = (
    "Target IP", "Target Hostname", "Target Port", "Start Time", "End Time",
    "host(s) tested", "Multiple IPs", "No CGI Directories", "item(s) reported",
    "Scan terminated", "ERROR:", "Server:", "Server No Banner",
)

# Frases de cabecera → nombre canónico (para de-dup con curl, B.11).
_HEADER_MAP = [
    ("x-frame-options", "x-frame-options"),
    ("x-content-type-options", "x-content-type-options"),
    ("strict-transport-security", "strict-transport-security"),
    ("content-security-policy", "content-security-policy"),
    ("referrer-policy", "referrer-policy"),
    ("permissions-policy", "permissions-policy"),
]


def _clean(desc: str) -> str:
    return re.sub(r"\s+", " ", desc).strip().rstrip(".")


def parse(path: str, ctx) -> list[FindingCandidate]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []

    out: list[FindingCandidate] = []
    for line in lines:
        line = line.strip()
        if not line.startswith("+ "):
            continue
        body = line[2:].strip()
        if any(s in body for s in _SKIP):
            continue

        # Separar "/ruta: descripción" si aplica.
        sistema = ctx.target_url
        desc = body
        m = re.match(r"^(/\S*)\s*:\s*(.+)$", body)
        if m:
            sistema = ctx.target_url.rstrip("/") + m.group(1)
            desc = m.group(2)
        desc = _clean(desc)
        if not desc:
            continue

        low = desc.lower()
        dedup = None
        for frase, name in _HEADER_MAP:
            if frase in low and ("not present" in low or "not set" in low
                                 or "no está" in low or "missing" in low):
                dedup = f"header-missing:{name}"
                break

        out.append(
            FindingCandidate(
                titulo=desc[:280],
                severidad=SEV_BAJA if dedup else SEV_INFO,
                estado=EST_A_VALIDAR,
                herramienta_origen="nikto",
                sistema_afectado=sistema,
                evidencia=f"nikto: {body[:280]}",
                cwe="CWE-200" if dedup else None,
                recomendacion="Verificar en validación de bajo nivel (nikto puede reportar falsos positivos).",
                dedup_key=dedup or f"nikto:{low[:120]}",
            )
        )
    return out
