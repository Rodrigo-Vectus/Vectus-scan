"""dig / subfinder → contexto (B.5/B.6).

No son vulnerabilidades: aportan mapa de superficie. Los subdominios se
filtran al dominio raíz (descartando ruido tipo MX). subfinder es pasivo y
no se escanea fuera del target (solo contexto).
"""
from worker.parsers import SEV_INFO, EST_CONFIRMADO, FindingCandidate


def parse_subfinder(path: str, ctx) -> list[FindingCandidate]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            subs = [l.strip() for l in f if l.strip()]
    except Exception:
        return []
    root = ctx.host.lower()
    subs = sorted({s.lower() for s in subs if s.lower().endswith(root)})
    if not subs:
        return []
    muestra = ", ".join(subs[:10]) + (" …" if len(subs) > 10 else "")
    return [
        FindingCandidate(
            titulo=f"Subdominios detectados (contexto): {len(subs)}",
            severidad=SEV_INFO,
            estado=EST_CONFIRMADO,
            herramienta_origen="subfinder",
            sistema_afectado=ctx.host,
            evidencia=muestra,
            recomendacion="Mapa de superficie. No se escanean activamente (fuera del target autorizado).",
            dedup_key="subfinder:subdominios",
        )
    ]


def parse_dig(path: str, ctx) -> list[FindingCandidate]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception:
        return []
    ips = []
    for l in lines:
        parts = l.split()
        if len(parts) >= 5 and parts[3] in ("A", "AAAA"):
            ips.append(parts[4])
    if not ips:
        return []
    return [
        FindingCandidate(
            titulo="Resolución DNS (contexto)",
            severidad=SEV_INFO,
            estado=EST_CONFIRMADO,
            herramienta_origen="dig",
            sistema_afectado=ctx.host,
            evidencia="IPs: " + ", ".join(sorted(set(ips))),
            recomendacion="Contexto de alcance. Verificar si la IP corresponde a CDN o al origen real.",
            dedup_key="dig:resolucion",
        )
    ]
