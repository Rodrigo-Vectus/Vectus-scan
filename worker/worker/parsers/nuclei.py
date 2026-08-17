"""nuclei -jsonl → vulnerabilidades y CVE (B.8).

Una línea JSON por match. Cada match es un Finding: severidad de B.2,
sistema_afectado = matched-at, cve/cwe de classification, mas_info = reference.
"""
import json

from worker.parsers import EST_CONFIRMADO, FindingCandidate, nuclei_severity


def _join(v) -> str:
    if not v:
        return ""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def parse(path: str, ctx) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue

        info = m.get("info") or {}
        classification = info.get("classification") or {}
        cve = _join(classification.get("cve-id")) or "No aplica"
        cwe = _join(classification.get("cwe-id")) or None
        refs = _join(info.get("reference")) or None
        matched = m.get("matched-at") or m.get("host") or ctx.target_url
        template = m.get("template-id") or ""

        out.append(
            FindingCandidate(
                titulo=info.get("name") or template or "Hallazgo nuclei",
                severidad=nuclei_severity(info.get("severity")),
                estado=EST_CONFIRMADO,
                herramienta_origen="nuclei",
                sistema_afectado=matched,
                evidencia=f"template: {template} · matched-at: {matched}",
                cve=cve,
                cwe=cwe,
                recomendacion=info.get("remediation") or "Aplicar la remediación indicada en las referencias.",
                mas_info=refs,
                dedup_key=f"nuclei:{template}:{matched}",
            )
        )
    return out
