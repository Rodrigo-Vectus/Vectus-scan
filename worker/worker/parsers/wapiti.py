"""Parser de la salida JSON de wapiti (F8c — detección activa de aplicación).

wapiti hace **detección activa no intrusiva**: envía payloads de prueba a los
parámetros/formularios y observa la respuesta para *detectar* la vulnerabilidad
(SQLi, XSS, inyección de comandos, LFI/traversal, SSRF, XXE, etc.). **No
explota** (no extrae datos ni toma control) — línea Nessus/Greenbone.

Formato JSON (wapiti 3.x):
  {
    "vulnerabilities": { "<Categoría>": [ {method, path, info, level,
        parameter, module, http_request, ...}, ... ], ... },
    "classifications": { "<Categoría>": {desc, sol, ref{...}, wstg[]}, ... },
    ...
  }
El `level` numérico se mapea a nuestra severidad; el CWE sale de las claves de
`classifications[cat]["ref"]`; `sol` alimenta la recomendación.
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


def _cwe_and_refs(classification: dict) -> tuple[str | None, list[str]]:
    """Extrae CWE y URLs de referencia de la ficha de la categoría."""
    cwe = None
    refs: list[str] = []
    for label, url in (classification.get("ref") or {}).items():
        m = _CWE_RE.search(label)
        if m and cwe is None:
            cwe = m.group(0).upper()
        if url:
            refs.append(url)
    return cwe, refs[:5]


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
        cwe, refs = _cwe_and_refs(classifications.get(category, {}))
        sol = (classifications.get(category, {}) or {}).get("sol") or ""

        for it in items:
            level = it.get("level", 0)
            sev = _LEVEL_SEV.get(level, SEV_INFO)
            param = it.get("parameter") or ""
            path_ = it.get("path") or "/"
            method = it.get("method") or "GET"
            info = it.get("info") or category

            titulo = f"{category}"
            if param:
                titulo += f" (parámetro '{param}')"

            evidencia = f"{info} — {method} {path_}"
            http_req = it.get("http_request") or ""
            if http_req:
                evidencia += f"\nRequest de prueba:\n{http_req[:400]}"

            out.append(
                FindingCandidate(
                    titulo=titulo,
                    severidad=sev,
                    estado=EST_CONFIRMADO,  # wapiti confirma probando activamente
                    herramienta_origen="wapiti",
                    sistema_afectado=f"{target}{path_}" if path_ != "/" else target,
                    evidencia=evidencia,
                    cwe=cwe or "No aplica",
                    recomendacion=sol or "Revisar y remediar la vulnerabilidad detectada.",
                    mas_info=" | ".join(refs) if refs else "",
                    dedup_key=f"wapiti:{category.lower()}:{path_}:{param}",
                )
            )
    return out
