"""Cliente de OSV.dev para validar versiones de paquetes contra CVEs (F8a).

OSV.dev (Google/OpenSSF) responde, para un paquete + ecosistema + versión
exacta, los advisories que la afectan, con severidad (CVSS), alias (CVE/GHSA)
y referencias. Es una **consulta a un tercero**, no una acción contra el
objetivo: no toca el target ni cambia el principio rector.

Diseño:
- **stdlib `urllib`** (sin dependencias nuevas).
- **Cache por proceso** (mismo paquete+versión no se consulta dos veces).
- **Degradación elegante**: ante cualquier error/timeout, `query()` devuelve
  `None` (≠ lista vacía). El consumidor distingue:
    * `None`  → no se pudo validar (dejar el hallazgo como estaba + nota).
    * `[]`    → validado, sin vulnerabilidades.
    * `[...]` → vulnerable (lista de advisories normalizados).
"""
import json
import urllib.request
from urllib.error import URLError

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_DEFAULT_TIMEOUT = 12  # segundos

# Cache por proceso: (ecosystem, package, version) → resultado normalizado.
_CACHE: dict[tuple[str, str, str], list | None] = {}


def _http_post(url: str, payload: dict, timeout: int) -> dict | None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "vectus-scan/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, TimeoutError, ValueError, OSError):
        return None


# ─── Cálculo de CVSS 3.x base score (determinístico, sin dependencias) ──────
# Fórmula oficial FIRST CVSS v3.1 (idéntica base en 3.0). Se usa para derivar
# nuestra severidad y llenar cvss/cvss_vector del hallazgo.

_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope Unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},    # Scope Changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    # "Roundup" de la spec CVSS v3.1 (al alza a 1 decimal).
    import math
    return math.ceil(x * 10) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Devuelve el base score CVSS 3.x a partir del vector, o None si no parsea."""
    if not vector:
        return None
    try:
        parts = dict(
            kv.split(":", 1)
            for kv in vector.strip().split("/")
            if ":" in kv and not kv.startswith("CVSS")
        )
        av = _CVSS_W["AV"][parts["AV"]]
        ac = _CVSS_W["AC"][parts["AC"]]
        ui = _CVSS_W["UI"][parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = _CVSS_W["PR_C" if scope_changed else "PR_U"][parts["PR"]]
        c = _CVSS_W["CIA"][parts["C"]]
        i = _CVSS_W["CIA"][parts["I"]]
        a = _CVSS_W["CIA"][parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10)
    else:
        base = min(impact + exploitability, 10)
    return _roundup(base)


def _extract_cvss_vector(vuln: dict) -> str | None:
    """Saca el vector CVSS 3.x del bloque `severity` de un advisory OSV."""
    best = None
    for sev in vuln.get("severity") or []:
        stype = (sev.get("type") or "").upper()
        score = sev.get("score") or ""
        if stype in ("CVSS_V3", "CVSS_V3.1", "CVSS_V3_1") and "CVSS:3" in score:
            # Preferir 3.1 sobre 3.0 si aparecen ambos.
            if best is None or "CVSS:3.1" in score:
                best = score
    return best


def _cve_of(vuln: dict) -> str | None:
    for alias in vuln.get("aliases") or []:
        if str(alias).upper().startswith("CVE-"):
            return alias
    # Algunos records traen el CVE como id directamente.
    vid = vuln.get("id", "")
    return vid if str(vid).upper().startswith("CVE-") else None


def _label_severity(vuln: dict) -> str | None:
    """Severidad textual del advisory (GHSA database_specific), si está."""
    ds = vuln.get("database_specific") or {}
    return (ds.get("severity") or "").upper() or None


def _fixed_version(vuln: dict, ecosystem: str, package: str) -> str | None:
    """Primera versión 'fixed' del rango afectado que matchee el paquete."""
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def normalize(vuln: dict, ecosystem: str, package: str) -> dict:
    """Advisory OSV → dict chico y estable para el enriquecedor."""
    vector = _extract_cvss_vector(vuln)
    score = cvss3_base_score(vector) if vector else None
    return {
        "id": vuln.get("id"),
        "cve": _cve_of(vuln),
        "summary": vuln.get("summary") or vuln.get("details") or "",
        "cvss_vector": vector,
        "cvss_score": score,
        "label": _label_severity(vuln),
        "fixed": _fixed_version(vuln, ecosystem, package),
        "references": [
            r.get("url") for r in (vuln.get("references") or []) if r.get("url")
        ][:5],
    }


def query(
    ecosystem: str, package: str, version: str, timeout: int = _DEFAULT_TIMEOUT
) -> list | None:
    """Consulta OSV por paquete+versión. Devuelve lista de advisories
    normalizados, `[]` si no hay, o `None` si no se pudo validar."""
    key = (ecosystem, package, version)
    if key in _CACHE:
        return _CACHE[key]

    payload = {
        "package": {"ecosystem": ecosystem, "name": package},
        "version": version,
    }
    raw = _http_post(OSV_QUERY_URL, payload, timeout)
    if raw is None:
        _CACHE[key] = None  # no se pudo validar
        return None

    vulns = raw.get("vulns") or []
    result = [normalize(v, ecosystem, package) for v in vulns]
    _CACHE[key] = result
    return result


def clear_cache() -> None:
    _CACHE.clear()
