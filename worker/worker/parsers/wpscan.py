"""Parser de la salida JSON de WPScan (F8e).

Traduce el reporte de WPScan (core de WordPress + plugins + temas, con sus
vulnerabilidades conocidas cruzadas por versión) a hallazgos normalizados en
español, con CVE y una severidad **representativa** derivada del título de la
vulnerabilidad (WPScan no siempre trae CVSS).

Estado del hallazgo (F8f): la versión instalada de un plugin/tema es
autoritativa cuando WPScan logra detectarla —no hay backport de distro—, y en
ese caso el aviso se reporta **`confirmado`**. Cuando WPScan **no** detecta la
versión, lista *todas* las vulnerabilidades históricas del componente sin
saber si aplican a lo instalado: eso es una hipótesis, no un hecho, y se
reporta **`a_validar`**. Es el mismo criterio que D11 aplica al backport del
server-side.

Agrupación (F8f): los avisos de un mismo componente que comparten clase de
vulnerabilidad se emiten como **un solo hallazgo**, con el conteo, todos los
CVE y la versión de corrección más alta. WPScan reporta un aviso por widget o
por endpoint afectado (elementor llegó a 29 XSS), y volcarlos uno por uno
producía informes de cientos de filas que dicen lo mismo. No se pierde
información: el conteo y los CVE quedan en el hallazgo.
"""
import json
import re

from worker.parsers import (
    Ctx,
    EST_A_VALIDAR,
    EST_CONFIRMADO,
    FindingCandidate,
    SEV_ALTA,
    SEV_BAJA,
    SEV_CRITICA,
    SEV_MEDIA,
    SEV_ORDER,
)

# Heurística título → (severidad representativa, CWE). Conservadora: solo eleva
# a alta/crítica ante clases claramente graves; el resto queda en media.
#
# Los acrónimos van con \b (límite de palabra) porque son secuencias muy
# cortas que aparecen dentro de palabras corrientes del dominio. Sin eso,
# `rce` matcheaba dentro de "WooCommerce" —y de "Force", "Resource"— y todo
# plugin de WooCommerce terminaba como crítica con CWE-94. Mismo riesgo con
# `lfi`, `xss`, `sqli`, `csrf`, `xxe` y `ssrf`.
# (regex, severidad, CWE, slug de clase, etiqueta en español)
_RULES = [
    (re.compile(r"remote code|\brce\b|code execution|object injection", re.I),
     SEV_CRITICA, "CWE-94", "rce", "ejecución remota de código"),
    (re.compile(r"sql injection|\bsqli\b", re.I),
     SEV_CRITICA, "CWE-89", "sqli", "inyección SQL"),
    (re.compile(r"authentication bypass|auth bypass|privilege escalation", re.I),
     SEV_CRITICA, "CWE-287", "auth-bypass", "elevación de privilegios / evasión de autenticación"),
    (re.compile(r"arbitrary file (upload|write)|unrestricted file upload", re.I),
     SEV_CRITICA, "CWE-434", "file-upload", "carga de archivos sin restricción"),
    (re.compile(r"arbitrary file (read|download)|local file inclusion|\blfi\b|path traversal", re.I),
     SEV_ALTA, "CWE-22", "lfi", "lectura de archivos / salto de directorio"),
    (re.compile(r"\bssrf\b|server.side request", re.I),
     SEV_ALTA, "CWE-918", "ssrf", "falsificación de solicitudes del servidor (SSRF)"),
    (re.compile(r"xml external|\bxxe\b", re.I),
     SEV_ALTA, "CWE-611", "xxe", "entidades externas XML (XXE)"),
    (re.compile(r"cross.site scripting|\bxss\b", re.I),
     SEV_MEDIA, "CWE-79", "xss", "Cross-Site Scripting (XSS)"),
    (re.compile(r"cross.site request forgery|\bcsrf\b", re.I),
     SEV_MEDIA, "CWE-352", "csrf", "Cross-Site Request Forgery (CSRF)"),
    (re.compile(r"open redirect", re.I),
     SEV_MEDIA, "CWE-601", "open-redirect", "redirección abierta"),
    (re.compile(r"information disclosure|sensitive data|disclosure", re.I),
     SEV_MEDIA, "CWE-200", "disclosure", "divulgación de información"),
    (re.compile(r"missing authorization|unauthorized|broken access control", re.I),
     SEV_MEDIA, "CWE-862", "authz", "falta de control de autorización"),
]


def _clase(title: str) -> tuple[str, str, str, str]:
    """(severidad, CWE, slug, etiqueta) de un aviso, según su título."""
    for rx, sev, cwe, slug, etiqueta in _RULES:
        if rx.search(title or ""):
            return sev, cwe, slug, etiqueta
    # Vulnerabilidad conocida sin clase clara: media representativa.
    return SEV_MEDIA, "No aplica", "otra", "vulnerabilidad reportada"


def _sev_cwe(title: str) -> tuple[str, str]:
    """Compatibilidad: severidad y CWE de un título suelto."""
    sev, cwe, _slug, _et = _clase(title)
    return sev, cwe


# `Finding.cve` es VARCHAR(200) y un grupo grande junta decenas de CVE (el XSS
# de elementor trae 29). Se recorta a lo que entra y se indica cuántos quedaron
# afuera; la lista completa va en la evidencia, que es TEXT.
_CVE_MAX = 190


def _cve_field(cves: list[str]) -> str:
    if not cves:
        return "No aplica"
    dentro: list[str] = []
    for c in cves:
        if len(", ".join(dentro + [c])) > _CVE_MAX:
            break
        dentro.append(c)
    if not dentro:            # un solo CVE anormalmente largo
        return cves[0][:200]
    txt = ", ".join(dentro)
    faltan = len(cves) - len(dentro)
    if faltan:
        txt += f" y {faltan} más"
    return txt[:200]


def _vkey(v: str) -> tuple:
    """Clave de orden para comparar versiones tipo 5.9.2 / 3.20.2."""
    partes = re.findall(r"\d+", str(v or ""))
    return tuple(int(p) for p in partes) if partes else (0,)


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


def _emit_grupo(kind_es, name, version, avisos, target):
    """Un hallazgo por (componente, clase de vulnerabilidad).

    `version` es la que WPScan detectó, o "" si no pudo. Ese dato decide el
    estado: con versión el match es autoritativo (`confirmado`); sin versión
    solo sabemos que el componente TIENE vulnerabilidades conocidas, no que
    esta instalación las tenga (`a_validar`).
    """
    sev, cwe, slug, etiqueta = _clase(avisos[0].get("title"))
    # Dentro de una clase la severidad es la misma, pero se toma la peor por
    # las dudas (títulos que matchean reglas distintas del mismo slug no
    # existen hoy, y si aparecieran no queremos bajar la severidad).
    for v in avisos[1:]:
        s2 = _clase(v.get("title"))[0]
        if SEV_ORDER[s2] < SEV_ORDER[sev]:
            sev = s2

    cves, fixes, titulos = [], [], []
    for v in avisos:
        for c in _cves(v.get("references") or {}):
            if c not in cves:
                cves.append(c)
        if v.get("fixed_in"):
            fixes.append(str(v["fixed_in"]))
        t = (v.get("title") or "").strip()
        if t and t not in titulos:
            titulos.append(t)

    n = len(avisos)
    etiqueta_comp = f"{name} {version}".strip()
    titulo = f"{kind_es} vulnerable: {name} — {etiqueta}"
    if n > 1:
        titulo += f" ({n} avisos)"

    confirmado = bool(version)
    estado = EST_CONFIRMADO if confirmado else EST_A_VALIDAR

    partes = [f"{kind_es}: {etiqueta_comp}."]
    partes.append(
        f"WPScan reporta {n} aviso{'s' if n > 1 else ''} de esta clase para el componente."
    )
    if titulos:
        muestra = "; ".join(t[:110] for t in titulos[:4])
        partes.append(f"Avisos: {muestra}{' …' if len(titulos) > 4 else ''}")
    if len(cves) > 1:
        # La lista completa vive acá porque el campo `cve` está acotado.
        partes.append(f"CVE asociados ({len(cves)}): {', '.join(cves)}.")
    if not confirmado:
        partes.append(
            "WPScan no pudo determinar la versión instalada, por lo que lista las "
            "vulnerabilidades conocidas del componente sin cruzarlas contra esta "
            "instalación: requiere validación manual de la versión en uso."
        )
    evidencia = " ".join(partes)

    objetivo = max(fixes, key=_vkey) if fixes else None
    if confirmado and objetivo:
        recomendacion = (
            f"Actualizar {kind_es.lower()} «{name}» a la versión {objetivo} o superior. "
            f"La versión instalada ({version}) es autoritativa en WordPress: el número "
            f"confirma la exposición."
        )
    elif objetivo:
        recomendacion = (
            f"Verificar la versión instalada de «{name}» y, si es anterior a "
            f"{objetivo}, actualizar a esa versión o superior. WPScan no pudo "
            f"determinarla de forma remota."
        )
    else:
        recomendacion = (
            f"Actualizar {kind_es.lower()} «{name}» a la última versión mantenida "
            f"o reemplazarlo si está sin soporte."
        )

    refs = []
    for v in avisos:
        for u in _refs_urls(v.get("references") or {}):
            if u not in refs:
                refs.append(u)

    return FindingCandidate(
        titulo=titulo,
        severidad=sev,
        estado=estado,
        herramienta_origen="wpscan",
        sistema_afectado=target,
        evidencia=evidencia,
        cve=_cve_field(cves),
        cwe=cwe,
        recomendacion=recomendacion,
        mas_info=" | ".join(refs[:5]),
        ocurrencias=n,
        dedup_key=f"wpscan:{name.lower()}:{slug}",
    )


def _emitir(kind_es, name, version, vulns, target, out):
    """Agrupa los avisos de un componente por clase y emite un hallazgo c/u."""
    por_clase = {}
    for v in vulns or []:
        por_clase.setdefault(_clase(v.get("title"))[2], []).append(v)
    for avisos in por_clase.values():
        out.append(_emit_grupo(kind_es, name, version, avisos, target))


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

    # Core de WordPress. Acá la versión SIEMPRE viene del propio reporte, así
    # que estos hallazgos son confirmados.
    version = data.get("version") or {}
    wp_num = version.get("number") or ""
    _emitir("Núcleo de WordPress", "WordPress", wp_num,
            version.get("vulnerabilities"), target, out)

    # Plugins y temas: la versión puede faltar (WPScan no siempre la deduce).
    for kind_es, seccion in (("Plugin", "plugins"), ("Tema", "themes")):
        for slug, info in (data.get(seccion) or {}).items():
            ver = ((info or {}).get("version") or {}).get("number") or ""
            _emitir(kind_es, slug, ver, (info or {}).get("vulnerabilities"), target, out)

    return out
