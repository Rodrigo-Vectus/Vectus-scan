"""Tests de F8e (WPScan). El parser se prueba con un fixture con el formato real
de WPScan; el gate por WordPress se prueba con whatweb.json de fixture."""
import json
import os
import tempfile

from worker.parsers import wpscan
from worker.parsers import (
    Ctx,
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
    cf7 = by["wpscan:contact-form-7:cve-2020-35489"]
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
