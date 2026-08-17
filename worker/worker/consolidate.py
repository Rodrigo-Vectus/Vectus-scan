"""Consolidación de hallazgos (F3, B.11).

Lee el raw guardado de un scan, corre el parser de cada herramienta, de-duplica
los candidatos (mismo hallazgo desde tools distintas = un solo Finding con
`ocurrencias`) y reescribe la tabla `findings` del scan de forma idempotente.
"""
import os

from worker.db import SessionLocal
from worker.models import Finding, Scan
from worker.parsers import SEV_ORDER, FindingCandidate, Ctx
from worker.parsers import (
    context,
    curl_headers,
    ffuf,
    nikto,
    nmap_services,
    nmap_tls,
    nuclei,
    whatweb,
)
from worker.target import parse_target

DATA_ROOT = os.getenv("SCAN_DATA_ROOT", "/data/scans")

# filename → función de parseo. Se busca cada archivo dentro del árbol del scan.
_PARSERS = {
    "nmap_services.xml": nmap_services.parse,
    "nmap_tls.xml": nmap_tls.parse,
    "whatweb.json": whatweb.parse,
    "ffuf.json": ffuf.parse,
    "nuclei.jsonl": nuclei.parse,
    "headers.txt": curl_headers.parse,
    "nikto.txt": nikto.parse,
    "subfinder.txt": context.parse_subfinder,
    "dig.txt": context.parse_dig,
}

_EST_RANK = {"confirmado": 0, "a_validar": 1, "positivo": 2, "falso_positivo": 3}


def _collect(scan_dir: str, ctx: Ctx) -> list[FindingCandidate]:
    """Corre todos los parsers sobre los archivos presentes en el árbol."""
    found: list[FindingCandidate] = []
    for root, _dirs, files in os.walk(scan_dir):
        for fname in files:
            parser = _PARSERS.get(fname)
            if parser is None:
                continue
            try:
                found.extend(parser(os.path.join(root, fname), ctx))
            except Exception:
                # un parser que falla no rompe la consolidación
                continue
    return found


def _merge(cands: list[FindingCandidate]) -> list[FindingCandidate]:
    """De-duplica por clave semántica (B.11)."""
    groups: dict[str, list[FindingCandidate]] = {}
    for c in cands:
        groups.setdefault(c.key(), []).append(c)

    merged: list[FindingCandidate] = []
    for group in groups.values():
        # Representante: mayor severidad y, a igualdad, estado más "confirmado".
        rep = min(
            group,
            key=lambda c: (SEV_ORDER.get(c.severidad, 9), _EST_RANK.get(c.estado, 9)),
        )
        tools = sorted({c.herramienta_origen for c in group})
        rep.herramienta_origen = ", ".join(tools)
        rep.ocurrencias = sum(c.ocurrencias for c in group)
        merged.append(rep)
    return merged


def run(scan_id: int, data_root: str = DATA_ROOT) -> int:
    """Reconstruye los findings del scan a partir del raw. Devuelve el total."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return 0

        try:
            tgt = parse_target(scan.target)
            ctx = Ctx(target_url=tgt.url, host=tgt.host)
        except Exception:
            ctx = Ctx(target_url=scan.target or "", host=scan.target or "")

        scan_dir = os.path.join(data_root, str(scan_id))
        cands = _collect(scan_dir, ctx) if os.path.isdir(scan_dir) else []
        merged = _merge(cands)

        # Idempotente: borrar findings previos del scan y reescribir.
        db.query(Finding).filter(Finding.scan_id == scan_id).delete()
        for c in merged:
            db.add(
                Finding(
                    scan_id=scan_id,
                    titulo=c.titulo,
                    severidad=c.severidad,
                    cvss=c.cvss,
                    cvss_vector=c.cvss_vector,
                    sistema_afectado=c.sistema_afectado,
                    evidencia=c.evidencia,
                    herramienta_origen=c.herramienta_origen,
                    cve=c.cve,
                    cwe=c.cwe,
                    recomendacion=c.recomendacion,
                    mas_info=c.mas_info,
                    estado=c.estado,
                    ocurrencias=c.ocurrencias,
                    dedup_key=c.key(),
                )
            )
        db.commit()
        return len(merged)
    finally:
        db.close()
