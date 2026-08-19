"""Enriquecimiento de hallazgos por CVE vía OSV (F8a).

Toma los candidatos que llevan una pista de paquete (`FindingCandidate.pkg`,
seteada por whatweb/retire.js sobre librerías con versión), consulta OSV y:

- **Vulnerable**  → transforma el hallazgo *in place* en una vulnerabilidad
  **confirmada**: severidad derivada del CVSS de OSV, `estado=confirmado`, CVE,
  cvss/cvss_vector, recomendación de actualización y referencias.
- **No vulnerable** → lo deja como estaba (INFO "detectada").
- **No se pudo validar** (OSV inaccesible) → lo deja como estaba + nota.

La función es pura salvo por la `query` inyectada (OSV real en producción, un
doble en tests). No toca la base de datos.

Alcance de este incremento: **librerías cliente** (ecosistema npm). El
server-side sigue con su `version_review` (`a_validar`, salvedad de backport).
"""
from worker.parsers import (
    SEV_ALTA,
    SEV_BAJA,
    SEV_CRITICA,
    SEV_INFO,
    SEV_MEDIA,
    SEV_ORDER,
    EST_CONFIRMADO,
    cvss_to_severity,
)
from worker import osv as osv_mod

_LABEL_SEV = {
    "CRITICAL": SEV_CRITICA,
    "HIGH": SEV_ALTA,
    "MODERATE": SEV_MEDIA,
    "MEDIUM": SEV_MEDIA,
    "LOW": SEV_BAJA,
}


def _adv_severity(adv: dict) -> str:
    """Severidad interna de un advisory: del CVSS si hay, si no del label."""
    score = adv.get("cvss_score")
    if score is not None:
        return cvss_to_severity(score)
    label = (adv.get("label") or "").upper()
    if label in _LABEL_SEV:
        return _LABEL_SEV[label]
    return SEV_MEDIA  # advisory sin severidad explícita: conservador


def _worst(advisories: list[dict]) -> tuple[str, dict]:
    """Severidad más alta y el advisory que la origina (para cvss/vector)."""
    best_sev = SEV_INFO
    best_adv = advisories[0]
    for adv in advisories:
        sev = _adv_severity(adv)
        if SEV_ORDER[sev] < SEV_ORDER[best_sev]:
            best_sev = sev
            best_adv = adv
    return best_sev, best_adv


def _apply(cand, package: str, version: str, advisories: list[dict]) -> None:
    """Transforma el candidato de librería en una vuln confirmada."""
    sev, adv = _worst(advisories)

    cves = sorted({a["cve"] for a in advisories if a.get("cve")})
    ids = sorted({a["id"] for a in advisories if a.get("id")})
    fixes = sorted({a["fixed"] for a in advisories if a.get("fixed")})
    refs: list[str] = []
    for a in advisories:
        for r in a.get("references") or []:
            if r not in refs:
                refs.append(r)

    cand.titulo = f"Librería JS vulnerable: {package} {version}"
    cand.severidad = sev
    cand.estado = EST_CONFIRMADO
    cand.cve = ", ".join(cves) if cves else cand.cve
    cand.cvss = adv.get("cvss_score")
    cand.cvss_vector = adv.get("cvss_vector")
    cand.cwe = cand.cwe  # OSV no siempre trae CWE; se deja el existente

    resumen = adv.get("summary") or ""
    detalle = f"{package} {version} — advisories: {', '.join(ids)}."
    if resumen:
        detalle += f" {resumen}"
    cand.evidencia = detalle

    if fixes:
        cand.recomendacion = (
            f"Actualizar {package} a una versión corregida "
            f"(≥ {', '.join(fixes)}). Las librerías JS se sirven al cliente con "
            f"su versión exacta: el número confirma la exposición (no hay backport)."
        )
    else:
        cand.recomendacion = (
            f"Actualizar {package} a la última versión mantenida; la versión "
            f"servida {version} tiene advisories conocidos."
        )

    cand.mas_info = " | ".join(refs[:5]) if refs else "https://osv.dev/"


def enrich_osv(cands: list, query=osv_mod.query) -> list:
    """Recorre los candidatos con `pkg` y los enriquece vía OSV. In place."""
    for cand in cands:
        pkg = getattr(cand, "pkg", None)
        if not pkg:
            continue
        ecosystem, package, version = pkg
        if not version:
            continue
        try:
            advisories = query(ecosystem, package, version)
        except Exception:
            advisories = None

        if advisories is None:
            # No se pudo validar (OSV inaccesible): dejar como está + nota.
            nota = " · No se pudo validar contra OSV en este run (reintentar)."
            cand.recomendacion = (cand.recomendacion or "") + nota
            continue
        if not advisories:
            continue  # validado, sin vulnerabilidades: se deja como INFO

        _apply(cand, package, version, advisories)
    return cands
