"""Tests de F8e (WPScan). El parser se prueba con un fixture con el formato real
de WPScan; el gate por WordPress se prueba con whatweb.json de fixture."""
import json
import os
import tempfile

from worker.parsers import wpscan
from worker.parsers import (
    Ctx,
    EST_A_VALIDAR,
    EST_CONFIRMADO,
    SEV_ALTA,
    SEV_CRITICA,
    SEV_MEDIA,
)
from worker.tools import wpscan_run


def _report():
    return {
        "target_url": "http://wp.example/",
        "version": {
            "number": "5.7",
            "vulnerabilities": [
                {"title": "WordPress 5.7 - SQL Injection via WP_Query",
                 "fixed_in": "5.7.2",
                 "references": {"cve": ["2021-21661"], "url": ["https://wpscan.com/x"]}},
            ],
        },
        "plugins": {
            "contact-form-7": {
                "version": {"number": "5.3.1"},
                "vulnerabilities": [
                    {"title": "Contact Form 7 < 5.3.2 - Unrestricted File Upload",
                     "fixed_in": "5.3.2",
                     "references": {"cve": ["2020-35489"], "url": ["https://wpscan.com/y"]}},
                ],
            },
            "wp-super-cache": {
                "version": {"number": "1.7.1"},
                "vulnerabilities": [
                    {"title": "WP Super Cache 1.7.1 - Reflected Cross-Site Scripting (XSS)",
                     "fixed_in": "1.7.2", "references": {"cve": ["2021-24209"]}},
                ],
            },
        },
        "themes": {
            "twentytwenty": {
                "version": {"number": "1.2"},
                "vulnerabilities": [
                    {"title": "Twenty Twenty 1.2 - Information Disclosure",
                     "fixed_in": "1.3", "references": {}},
                ],
            },
        },
    }


def _write(tmp, data, name="wpscan.json"):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return p


def test_parse_core_plugins_themes():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, _report())
        cands = wpscan.parse(path, Ctx(target_url="http://wp.example/"))

    by = {c.dedup_key: c for c in cands}
    # Core: SQLi → crítica, CVE normalizado.
    core = [c for c in cands if c.titulo.startswith("Núcleo de WordPress")][0]
    assert core.severidad == SEV_CRITICA
    assert core.cve == "CVE-2021-21661"
    assert core.estado == EST_CONFIRMADO

    # Plugin file upload → crítica; recomendación en español con fixed_in.
    # F8f: el dedup_key pasó de <cve> a <clase>, para agrupar los avisos de
    # una misma clase en un solo hallazgo.
    cf7 = by["wpscan:contact-form-7:file-upload"]
    assert cf7.severidad == SEV_CRITICA
    assert "5.3.2" in cf7.recomendacion
    assert "Plugin vulnerable: contact-form-7" in cf7.titulo

    # Plugin XSS → media.
    xss = [c for c in cands if "wp-super-cache" in c.dedup_key][0]
    assert xss.severidad == SEV_MEDIA
    assert xss.cwe == "CWE-79"

    # Tema info disclosure → media.
    theme = [c for c in cands if c.titulo.startswith("Tema vulnerable")][0]
    assert theme.severidad == SEV_MEDIA
    assert theme.cve == "No aplica"


def test_gated_and_error_return_empty():
    with tempfile.TemporaryDirectory() as tmp:
        assert wpscan.parse(_write(tmp, {"gated": "not_wordpress"}), Ctx()) == []
        assert wpscan.parse(_write(tmp, {"error": "x"}), Ctx()) == []


def test_bad_file_safe():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "wpscan.json")
        open(p, "w").write("no-json")
        assert wpscan.parse(p, Ctx()) == []


# ─── Gate por WordPress (whatweb) ───────────────────────────────────

def test_is_wordpress_gate():
    with tempfile.TemporaryDirectory() as scan:
        recon = os.path.join(scan, "1_reconocimiento")
        os.makedirs(recon)
        # whatweb detecta WordPress.
        with open(os.path.join(recon, "whatweb.json"), "w") as f:
            json.dump([{"target": "http://t/", "plugins": {"WordPress": {"version": ["5.7"]}, "PHP": {}}}], f)
        assert wpscan_run._is_wordpress(scan) is True


def test_is_not_wordpress():
    with tempfile.TemporaryDirectory() as scan:
        recon = os.path.join(scan, "1_reconocimiento")
        os.makedirs(recon)
        with open(os.path.join(recon, "whatweb.json"), "w") as f:
            json.dump([{"target": "http://t/", "plugins": {"Apache": {}, "PHP": {}}}], f)
        assert wpscan_run._is_wordpress(scan) is False


def test_gate_no_whatweb_is_false():
    with tempfile.TemporaryDirectory() as scan:
        assert wpscan_run._is_wordpress(scan) is False


# ─── F8f: los acrónimos de la heurística necesitan límite de palabra ──

def test_acronimos_no_matchean_dentro_de_palabras():
    """`rce` matcheaba dentro de "WooCommerce" y todo plugin de WooCommerce
    salía crítica con CWE-94. Mismo riesgo con Force/Resource y con el resto
    de los acrónimos cortos."""
    from worker.parsers.wpscan import _sev_cwe

    for titulo in (
        "YITH WooCommerce Product Add-Ons < 4.13.1 - Reflected Cross-Site Scripting",
        "WooCommerce Wholesale Pricing < 2.0 - Reflected Cross-Site Scripting",
    ):
        sev, cwe = _sev_cwe(titulo)
        assert sev == SEV_MEDIA, f"«{titulo}» no es un XSS medio: {sev}"
        assert cwe == "CWE-79"

    # "Brute Force" y "Resource" tampoco deben leerse como RCE.
    assert _sev_cwe("Plugin < 1.2 - Brute Force protection bypass")[1] != "CWE-94"
    assert _sev_cwe("Plugin < 1.2 - Resource exhaustion")[1] != "CWE-94"


def test_las_clases_graves_siguen_elevando():
    """El fix no debe volver inofensivo lo que sí es grave."""
    from worker.parsers.wpscan import _sev_cwe

    casos = [
        ("Plugin < 4.29.1 - Authenticated (Shop manager+) SQL Injection", SEV_CRITICA, "CWE-89"),
        ("Plugin < 4.3.1 - Authenticated PHP Object Injection", SEV_CRITICA, "CWE-94"),
        ("Plugin < 2.0 - Unauthenticated Remote Code Execution", SEV_CRITICA, "CWE-94"),
        ("Plugin < 2.0 - RCE via file upload", SEV_CRITICA, "CWE-94"),
        ("Plugin < 2.1.0 - Authenticated Local File Inclusion", SEV_ALTA, "CWE-22"),
        ("Plugin < 3.0 - SSRF in webhook handler", SEV_ALTA, "CWE-918"),
        ("Plugin < 3.0 - Authentication Bypass", SEV_CRITICA, "CWE-287"),
    ]
    for titulo, sev_esperada, cwe_esperado in casos:
        sev, cwe = _sev_cwe(titulo)
        assert (sev, cwe) == (sev_esperada, cwe_esperado), f"«{titulo}» → {sev}/{cwe}"


def test_distribucion_realista_de_un_plugin():
    """Los 10 avisos reales de yith-woocommerce-product-add-ons: antes daban
    9 críticas por el bug de `rce`; la intención de D34 son 2."""
    from collections import Counter
    from worker.parsers.wpscan import _sev_cwe

    titulos = [
        "YIT Plugin Framework < 3.3.13 - Subscriber+ Settings Update",
        "YITH WooCommerce Product Add-Ons < 2.1.0 - Authenticated Local File Inclusion",
        "YITH WooCommerce Product Add-Ons < 2.1.0 - Reflected Cross-Site Scripting",
        "YITH WooCommerce Product Add-Ons < 4.2.1 - Missing Authorization",
        "YITH WooCommerce Product Add-Ons < 4.3.1 - Authenticated(Shop Manager+) PHP Object Injection",
        "YITH WooCommerce Product Add-Ons < 4.6.0 - Unuathenticated Cross-Site Scripting",
        "YITH WooCommerce Product Add-Ons < 4.9.3 - Unauthenticated Content Injection",
        "YITH WooCommerce Product Add-Ons < 4.13.1 - Reflected Cross-Site Scripting",
        "YITH WooCommerce Product Add-Ons < 4.14.2 - Reflected Cross-Site Scripting",
        "YITH WooCommerce Product Add-Ons < 4.29.1 - Authenticated (Shop manager+) SQL Injection",
    ]
    c = Counter(_sev_cwe(t)[0] for t in titulos)
    assert c[SEV_CRITICA] == 2
    assert c[SEV_ALTA] == 1
    assert c[SEV_MEDIA] == 7


# ─── F8f: estado según versión detectada, y agrupación por clase ─────

def _rep(plugins):
    return {"version": {"number": "6.8", "vulnerabilities": []},
            "plugins": plugins, "themes": {}}


def _aviso(titulo, cve=None, fixed=None):
    r = {"title": titulo, "fixed_in": fixed, "references": {}}
    if cve:
        r["references"]["cve"] = cve
    return r


def _parse(data):
    import json, os, tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
        path = fh.name
    try:
        return wpscan.parse(path, Ctx(target_url="https://x.test", host="x.test"))
    finally:
        os.unlink(path)


def test_sin_version_va_a_validar():
    """WPScan sin versión lista TODAS las vulns históricas del componente: no
    se puede afirmar que esta instalación las tenga."""
    out = _parse(_rep({"algo": {"version": None, "vulnerabilities": [
        _aviso("Algo < 2.0 - Reflected Cross-Site Scripting", ["2024-1"], "2.0"),
    ]}}))
    assert len(out) == 1
    assert out[0].estado == EST_A_VALIDAR
    assert "no pudo determinar la versión" in out[0].evidencia
    # La recomendación pide verificar, no afirma la exposición.
    assert "Verificar la versión instalada" in out[0].recomendacion


def test_con_version_sigue_confirmado():
    out = _parse(_rep({"algo": {"version": {"number": "1.5"}, "vulnerabilities": [
        _aviso("Algo < 2.0 - Reflected Cross-Site Scripting", ["2024-1"], "2.0"),
    ]}}))
    assert out[0].estado == EST_CONFIRMADO
    assert "autoritativa" in out[0].recomendacion


def test_agrupa_por_clase_y_conserva_cves_y_conteo():
    avisos = [
        _aviso(f"Plug < 3.{i}.0 - Authenticated Stored Cross-Site Scripting", [f"2022-{i}"], f"3.{i}.0")
        for i in range(5)
    ]
    avisos.append(_aviso("Plug < 4.0 - SQL Injection", ["2023-9"], "4.0"))
    out = _parse(_rep({"plug": {"version": {"number": "2.0"}, "vulnerabilities": avisos}}))

    # 6 avisos → 2 hallazgos (una clase XSS agrupada + un SQLi)
    assert len(out) == 2
    xss = [c for c in out if c.cwe == "CWE-79"][0]
    assert xss.ocurrencias == 5
    assert "(5 avisos)" in xss.titulo
    # No se pierde ningún CVE.
    for i in range(5):
        assert f"CVE-2022-{i}" in xss.cve
    # La recomendación apunta a la versión de corrección MÁS ALTA.
    assert "3.4.0" in xss.recomendacion


def test_el_titulo_identifica_la_clase():
    """Antes todos los avisos de un plugin salían con el mismo título y no se
    distinguían entre sí en el informe."""
    out = _parse(_rep({"cf7": {"version": None, "vulnerabilities": [
        _aviso("CF7 < 5.9.2 - Reflected Cross-Site Scripting", ["2024-1"], "5.9.2"),
        _aviso("CF7 < 5.3.2 - Unrestricted File Upload", ["2020-1"], "5.3.2"),
        _aviso("CF7 < 5.0.4 - Privilege Escalation", ["2018-1"], "5.0.4"),
    ]}}))
    titulos = {c.titulo for c in out}
    assert len(titulos) == 3, titulos
    assert any("Cross-Site Scripting" in t for t in titulos)
    assert any("carga de archivos" in t for t in titulos)
    assert any("privilegios" in t for t in titulos)


def test_dedup_key_por_componente_y_clase():
    out = _parse(_rep({"plug": {"version": {"number": "1.0"}, "vulnerabilities": [
        _aviso("Plug < 2.0 - Reflected XSS", ["2024-1"], "2.0"),
        _aviso("Plug < 3.0 - Stored XSS", ["2024-2"], "3.0"),
    ]}}))
    assert len(out) == 1
    assert out[0].dedup_key == "wpscan:plug:xss"


def test_version_de_correccion_ordena_numericamente():
    """3.20.2 es MAYOR que 3.9.0: comparar como texto daría al revés."""
    out = _parse(_rep({"plug": {"version": {"number": "1.0"}, "vulnerabilities": [
        _aviso("Plug < 3.9.0 - Reflected XSS", ["2024-1"], "3.9.0"),
        _aviso("Plug < 3.20.2 - Stored XSS", ["2024-2"], "3.20.2"),
    ]}}))
    assert "3.20.2" in out[0].recomendacion


def test_cve_no_desborda_la_columna():
    """`Finding.cve` es VARCHAR(200). Un grupo con decenas de avisos hacía
    fallar la consolidación entera con StringDataRightTruncation."""
    avisos = [
        _aviso(f"Plug < 3.{i}.0 - Stored Cross-Site Scripting", [f"2022-{10000+i}"], f"3.{i}.0")
        for i in range(29)
    ]
    out = _parse(_rep({"plug": {"version": {"number": "1.0"}, "vulnerabilities": avisos}}))
    assert len(out) == 1
    c = out[0]
    assert len(c.cve) <= 200, len(c.cve)
    assert "más" in c.cve                      # avisa que hay más
    assert c.ocurrencias == 29
    # La lista completa no se pierde: queda en la evidencia (TEXT).
    assert "CVE asociados (29)" in c.evidencia
    assert "CVE-2022-10028" in c.evidencia


def test_cve_corto_no_se_trunca():
    out = _parse(_rep({"plug": {"version": {"number": "1.0"}, "vulnerabilities": [
        _aviso("Plug < 2.0 - Reflected XSS", ["2024-1"], "2.0"),
    ]}}))
    assert out[0].cve == "CVE-2024-1"
