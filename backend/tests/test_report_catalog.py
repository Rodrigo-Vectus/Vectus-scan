"""Test de la localización del catálogo para hallazgos de wapiti (F8d)."""
from app.report_catalog import CATALOG, enrich, tipo_de


def test_tipo_de_maps_wapiti_slugs():
    assert tipo_de("wapiti:sqli:/page:id") == "wapiti-sqli"
    assert tipo_de("wapiti:path-traversal:/f:item") == "wapiti-path-traversal"
    assert tipo_de("wapiti:xss:/s:q") == "wapiti-xss"
    # Slug sin ficha → None (el informe cae a los datos del hallazgo).
    assert tipo_de("wapiti:weird-new-thing:/x:p") is None


def test_enrich_wapiti_is_spanish():
    vuln = {
        "dedup_key": "wapiti:sqli:/page:id",
        "severidad": "alta",
        "titulo": "Inyección SQL (parámetro 'id')",
        "cve": "No aplica",
        "cwe": "CWE-89",
        "evidencia": "Detectado por wapiti ...",
        "recomendacion": "(genérica del parser)",
        "cvss": None,
    }
    out = enrich(vuln)
    # La descripción/recomendación vienen de la ficha en español, no del inglés.
    assert "inyección sql" in out["descripcion"].lower()
    assert "parametrizadas" in out["recomendacion"].lower()
    assert out["cwe"] == "CWE-89"
    # CVSS: al ser ficha con cvss {}, usa el desglose por severidad (alta → 7.5).
    assert out["cvss"] == "7.5"


def test_all_wapiti_fichas_have_required_fields():
    for key, ficha in CATALOG.items():
        if not key.startswith("wapiti-"):
            continue
        assert set(ficha) >= {"cwe", "descripcion", "recomendacion", "mas_info", "cvss"}
        assert ficha["descripcion"] and ficha["recomendacion"]
