"""Parser de la salida del detector retire.js (F8b).

Cada detección (componente + versión) se emite como `FindingCandidate` de
librería, con el **mismo `dedup_key` `lib:<comp>`** que usa whatweb (para que
se fusionen si ambos la ven) y con la pista `pkg=(npm, paquete, versión)` para
que el enriquecedor OSV (F8a) la valide y confirme si es vulnerable.

Este parser solo **detecta**; la confirmación de vulnerabilidad la hace OSV.
"""
import json

from worker.parsers import Ctx, EST_CONFIRMADO, FindingCandidate, SEV_INFO
from worker.tools.retirejs import RETIRE_TO_NPM


def parse(path: str, ctx: Ctx) -> list[FindingCandidate]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            detections = json.load(f)
    except (OSError, ValueError):
        return []
    if not isinstance(detections, list):
        return []

    target = ctx.target_url or ctx.host or ""
    out: list[FindingCandidate] = []
    seen: set[tuple] = set()

    for det in detections:
        comp = str(det.get("component") or "").strip()
        version = str(det.get("version") or "").strip()
        if not comp or not version:
            continue
        if (comp, version) in seen:
            continue
        seen.add((comp, version))

        npm = RETIRE_TO_NPM.get(comp.lower())
        pkg = ("npm", npm, version) if npm else None
        source = det.get("source") or ""

        out.append(
            FindingCandidate(
                titulo=f"Librería front-end detectada: {comp} ({version})",
                severidad=SEV_INFO,
                estado=EST_CONFIRMADO,
                herramienta_origen="retire.js",
                sistema_afectado=target,
                evidencia=f"{comp}: {version} (retire.js @ {source})",
                recomendacion=(
                    "Verificar CVEs conocidos de la versión (validación automática vía OSV)."
                ),
                dedup_key=f"lib:{comp.lower()}",
                pkg=pkg,
            )
        )
    return out
