"""Tests de F9f: descripción del informe con desglose.

La descripción del .docx pasó de ser un volcado de la evidencia (o el texto
plano de la ficha) a un desglose: qué es y por qué importa, qué se observó en
este objetivo, y con qué se detectó.
"""
from app.report_catalog import CATALOG, descripcion_bloques, enrich, tipo_de


def _v(**kw):
    base = {
        "dedup_key": "", "titulo": "", "severidad": "media", "evidencia": "",
        "herramienta_origen": "", "cve": "No aplica", "cwe": None,
        "recomendacion": "—", "mas_info": "—", "sistema": "https://x.test",
        "ocurrencias": 1, "cvss": None,
    }
    base.update(kw)
    return base


# ─── mapeo de las familias que antes no tenían ficha ────────────────

def test_tipo_de_libreria_js():
    assert tipo_de("lib:jquery") == "js-library"
    assert tipo_de("lib:moment") == "js-library"


def test_tipo_de_wpscan_usa_el_titulo():
    # El dedup_key lleva el NOMBRE del componente, no su tipo: plugin, tema y
    # núcleo se distinguen por el título que emite el parser.
    k = "wpscan:pixelyoursite:cve-2024-1"
    assert tipo_de(k, "Plugin vulnerable: pixelyoursite") == "wpscan-plugin"
    assert tipo_de("wpscan:twentytwenty:cve-1", "Tema vulnerable: twentytwenty") == "wpscan-theme"
    assert tipo_de("wpscan:wordpress 6.4:cve-2",
                   "Núcleo de WordPress vulnerable: WordPress 6.4") == "wpscan-core"
    # Sin título, cae a plugin (el caso más frecuente) y no rompe.
    assert tipo_de(k) == "wpscan-plugin"


def test_fichas_nuevas_completas():
    for key in ("js-library", "wpscan-plugin", "wpscan-theme", "wpscan-core"):
        ficha = CATALOG[key]
        assert set(ficha) >= {"cwe", "descripcion", "recomendacion", "mas_info", "cvss"}
        assert len(ficha["descripcion"]) > 200  # contexto real, no una línea


# ─── composición de la descripción ──────────────────────────────────

def test_descripcion_combina_ficha_y_hallazgo():
    out = enrich(_v(
        dedup_key="lib:jquery",
        titulo="Librería JS vulnerable: jquery 3.1.1",
        evidencia="jquery 3.1.1 — advisories: GHSA-xxxx.",
        herramienta_origen="retire.js, whatweb",
    ))
    bloques = out["descripcion_bloques"]
    assert len(bloques) == 3
    # 1) contexto de la ficha
    assert "navegador" in bloques[0].lower()
    # 2) el dato concreto de ESTE objetivo, no perdido
    assert "GHSA-xxxx" in bloques[1]
    # 3) trazabilidad de la detección, en español
    assert "retire.js" in bloques[2] and "whatweb" in bloques[2]
    assert "no ejecuta explotación" in bloques[2]


def test_sin_ficha_la_evidencia_no_se_rotula():
    """Sin ficha la evidencia ES la descripción; rotularla como 'Hallazgo
    observado' dejaría el bloque colgando sin nada que lo introduzca."""
    bloques = descripcion_bloques(
        _v(dedup_key="nuclei:algo", titulo="Algo", evidencia="Coincidencia X.",
           herramienta_origen="nuclei"),
        None,
    )
    assert bloques[0] == "Coincidencia X."
    assert not bloques[0].startswith("Hallazgo observado")


def test_no_se_repiten_campos_que_ya_tiene_la_plantilla():
    """Sistema afectado, CVE y ocurrencias tienen su propio lugar en el .docx."""
    texto = " ".join(descripcion_bloques(
        _v(dedup_key="lib:jquery", titulo="Librería JS vulnerable: jquery 3.1.1",
           evidencia="jquery 3.1.1.", herramienta_origen="whatweb",
           cve="CVE-2019-11358", sistema="https://objetivo.test", ocurrencias=4),
        CATALOG["js-library"],
    ))
    assert "https://objetivo.test" not in texto
    assert "CVE-2019-11358" not in texto
    assert "4 veces" not in texto


def test_no_inventa_bloques_vacios():
    bloques = descripcion_bloques(_v(titulo="Solo un título"), None)
    assert bloques == ["Solo un título"]


def test_recomendacion_especifica_gana_sobre_la_generica():
    """La del hallazgo trae la versión de corrección; la de la ficha es
    genérica. Se conservan las dos, con la específica adelante."""
    out = enrich(_v(
        dedup_key="wpscan:pixelyoursite:cve-2024-1",
        titulo="Plugin vulnerable: pixelyoursite",
        recomendacion="Actualizar plugin «pixelyoursite» a la versión 9.6.0 o superior.",
        evidencia="Plugin: pixelyoursite.",
    ))
    assert out["recomendacion"].startswith("Actualizar plugin «pixelyoursite»")
    assert "sin mantenimiento" in out["recomendacion"] or "desinstalar" in out["recomendacion"]


def test_wapiti_sigue_en_espanol():
    """No romper F8d: las fichas de wapiti siguen mandando en la descripción."""
    out = enrich(_v(
        dedup_key="wapiti:sqli:/page:id", severidad="alta",
        titulo="Inyección SQL (parámetro 'id')", cwe="CWE-89",
        evidencia="Detectado por wapiti en /page.", herramienta_origen="wapiti",
    ))
    assert "inyección sql" in out["descripcion"].lower()
    assert out["cvss"] == "7.5"
