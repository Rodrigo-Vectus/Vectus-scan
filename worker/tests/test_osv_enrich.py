"""Tests de F8a (validación de versiones por OSV). Sin red ni DB: la consulta
OSV se inyecta como doble y el cálculo CVSS se verifica contra vectores
conocidos."""
import json
import os
import tempfile

from worker import osv
from worker.enrich import enrich_osv
from worker.parsers import (
    FindingCandidate,
    SEV_INFO,
    SEV_MEDIA,
    SEV_CRITICA,
    EST_CONFIRMADO,
    EST_A_VALIDAR,
    Ctx,
)
from worker.parsers import whatweb


# ─── CVSS 3.1 base score ────────────────────────────────────────────

def test_cvss_jquery_xss():
    # CVE-2020-11022 (jQuery): vector oficial → 6.1
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    assert osv.cvss3_base_score(v) == 6.1


def test_cvss_critical():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert osv.cvss3_base_score(v) == 9.8


def test_cvss_none_impact():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert osv.cvss3_base_score(v) == 0.0


def test_cvss_bad_vector():
    assert osv.cvss3_base_score("no-es-un-vector") is None
    assert osv.cvss3_base_score("") is None


# ─── Normalización de un record OSV crudo ───────────────────────────

def _raw_osv_vuln():
    return {
        "id": "GHSA-gxr4-xjj5-5px2",
        "aliases": ["CVE-2020-11022"],
        "summary": "XSS en jQuery",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}
        ],
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "jquery"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.2.0"}, {"fixed": "3.5.0"}]}
                ],
            }
        ],
        "references": [{"type": "WEB", "url": "https://blog.jquery.com/"}],
    }


def test_normalize():
    n = osv.normalize(_raw_osv_vuln(), "npm", "jquery")
    assert n["cve"] == "CVE-2020-11022"
    assert n["cvss_score"] == 6.1
    assert n["fixed"] == "3.5.0"
    assert n["references"] == ["https://blog.jquery.com/"]


# ─── Enriquecimiento ────────────────────────────────────────────────

def _lib_candidate():
    return FindingCandidate(
        titulo="Librería front-end detectada: jQuery (3.3.1)",
        severidad=SEV_INFO,
        herramienta_origen="whatweb",
        sistema_afectado="http://t.example/",
        dedup_key="lib:jquery",
        pkg=("npm", "jquery", "3.3.1"),
    )


def test_enrich_vulnerable_upgrades():
    cand = _lib_candidate()

    def fake_query(eco, pkg, ver):
        assert (eco, pkg, ver) == ("npm", "jquery", "3.3.1")
        return [osv.normalize(_raw_osv_vuln(), "npm", "jquery")]

    enrich_osv([cand], query=fake_query)
    assert cand.estado == EST_CONFIRMADO
    assert cand.severidad == SEV_MEDIA          # 6.1 → media
    assert cand.cve == "CVE-2020-11022"
    assert cand.cvss == 6.1
    assert "vulnerable" in cand.titulo.lower()
    assert "3.5.0" in (cand.recomendacion or "")


def test_enrich_picks_worst_of_many():
    cand = _lib_candidate()
    crit = osv.normalize(_raw_osv_vuln(), "npm", "jquery")
    crit["cvss_score"] = 9.8
    crit["cvss_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    crit["cve"] = "CVE-2019-9999"
    moderate = osv.normalize(_raw_osv_vuln(), "npm", "jquery")

    enrich_osv([cand], query=lambda *_: [moderate, crit])
    assert cand.severidad == SEV_CRITICA
    assert cand.cvss == 9.8
    # Junta los dos CVEs.
    assert "CVE-2019-9999" in cand.cve and "CVE-2020-11022" in cand.cve


def test_enrich_not_vulnerable_leaves_info():
    cand = _lib_candidate()
    enrich_osv([cand], query=lambda *_: [])
    assert cand.estado == EST_CONFIRMADO  # el default del candidato
    assert cand.severidad == SEV_INFO
    assert "detectada" in cand.titulo.lower()


def test_enrich_osv_unavailable_adds_note():
    cand = _lib_candidate()
    enrich_osv([cand], query=lambda *_: None)
    assert cand.severidad == SEV_INFO           # sin cambios de severidad
    assert "no se pudo validar" in (cand.recomendacion or "").lower()


def test_enrich_ignores_candidates_without_pkg():
    other = FindingCandidate(
        titulo="Otro hallazgo", severidad=SEV_MEDIA, herramienta_origen="nuclei"
    )
    called = []
    enrich_osv([other], query=lambda *a: called.append(a) or [])
    assert called == []  # nunca consultó OSV
    assert other.titulo == "Otro hallazgo"


def test_enrich_query_exception_is_safe():
    cand = _lib_candidate()

    def boom(*_):
        raise RuntimeError("red caída")

    # No debe propagar; se trata como "no validado".
    enrich_osv([cand], query=boom)
    assert cand.severidad == SEV_INFO


# ─── Parser whatweb: adjunta la pista pkg ────────────────────────────

def _write(tmp, name, content):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


def test_whatweb_attaches_pkg_hint():
    data = [{
        "target": "http://t.example/",
        "plugins": {
            "jQuery": {"version": ["3.3.1"]},
            "Bootstrap": {"version": ["4.4.1"]},
            "Moment.js": {"version": ["2.24.0"]},
            "HTTPServer": {"string": ["Apache/2.4.6 (CentOS)"]},
        },
    }]
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "whatweb.json", json.dumps(data))
        cands = whatweb.parse(path, Ctx(target_url="http://t.example/", host="t.example"))

    libs = {c.dedup_key: c for c in cands if c.dedup_key.startswith("lib:")}
    assert libs["lib:jquery"].pkg == ("npm", "jquery", "3.3.1")
    assert libs["lib:bootstrap"].pkg == ("npm", "bootstrap", "4.4.1")
    assert libs["lib:moment.js"].pkg == ("npm", "moment", "2.24.0")
    # El server-side sigue generando su version_review a_validar (backport).
    assert any(
        c.estado == EST_A_VALIDAR and "apache" in (c.dedup_key or "")
        for c in cands
    )


def test_whatweb_no_version_no_pkg():
    # Plugin presente (truthy) pero sin campo `version`.
    data = [{"target": "http://t/", "plugins": {"jQuery": {"string": ["jquery.min.js"]}}}]
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "whatweb.json", json.dumps(data))
        cands = whatweb.parse(path, Ctx())
    jq = [c for c in cands if c.dedup_key == "lib:jquery"][0]
    assert jq.pkg is None  # sin versión → sin pista OSV


# ─── Integración parser → enriquecedor (con OSV falso) ──────────────

def test_whatweb_then_enrich_end_to_end():
    data = [{"target": "http://t/", "plugins": {"jQuery": {"version": ["3.3.1"]}}}]
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "whatweb.json", json.dumps(data))
        cands = whatweb.parse(path, Ctx())

    enrich_osv(cands, query=lambda *_: [osv.normalize(_raw_osv_vuln(), "npm", "jquery")])
    jq = [c for c in cands if c.dedup_key == "lib:jquery"][0]
    assert jq.estado == EST_CONFIRMADO and jq.cve == "CVE-2020-11022"
