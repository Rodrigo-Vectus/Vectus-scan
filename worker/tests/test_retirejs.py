"""Tests de F8b (detector retire.js en Python). Sin red: `fetch` se inyecta y
las firmas se cargan de un mini-repo fixture con el formato real de retire.js."""
import json
import os
import tempfile

from worker.tools import retirejs as rjs
from worker.parsers import retirejs as rjs_parser
from worker.parsers import Ctx, EST_CONFIRMADO, SEV_ALTA, SEV_INFO
from worker.enrich import enrich_osv
from worker import osv


# Mini-repo con el formato real de retire.js (extractors con §§version§§).
_REPO = {
    "jquery": {
        "extractors": {
            "uri": [r"/(§§version§§)/jquery(\.min)?\.js"],
            "filename": [r"jquery-(§§version§§)(\.min)?\.js"],
            "filecontent": [r"/\*!? jQuery v(§§version§§)"],
        }
    },
    "moment.js": {
        "extractors": {
            "filename": [r"moment(\.min)?\.js"],
            "filecontent": [r"//!? moment\.js(?:[\n\r]+)//!? version : (§§version§§)"],
        }
    },
}


def test_compile_and_detect_url():
    sigs = rjs.compile_signatures(_REPO)
    hits = rjs.detect_in_url("https://cdn.example/js/jquery-3.3.1.min.js", sigs)
    comps = {(c, v) for c, v, _ in hits}
    assert ("jquery", "3.3.1") in comps


def test_detect_content_moment():
    sigs = rjs.compile_signatures(_REPO)
    js = "//! moment.js\n//! version : 2.24.0\n//! authors ..."
    hits = rjs.detect_in_content(js, sigs)
    assert ("moment.js", "2.24.0", "filecontent") in hits


def test_scan_with_injected_fetch():
    pages = {
        "http://t/": '<html><head>'
                     '<script src="/js/jquery-3.3.1.min.js"></script>'
                     '<script src="/js/moment.min.js"></script>'
                     '</head></html>',
        "http://t/js/jquery-3.3.1.min.js": "/*! jQuery v3.3.1 */",
        "http://t/js/moment.min.js": "//! moment.js\n//! version : 2.24.0\n",
    }
    dets = rjs.scan("http://t/", _REPO, fetch=lambda u: pages.get(u), throttle=0)
    got = {(d["component"], d["version"]) for d in dets}
    assert ("jquery", "3.3.1") in got
    assert ("moment.js", "2.24.0") in got


def test_scan_network_down_is_safe():
    assert rjs.scan("http://t/", _REPO, fetch=lambda u: None, throttle=0) == []


def test_retire_to_npm_mapping():
    assert rjs.RETIRE_TO_NPM["moment.js"] == "moment"
    assert rjs.RETIRE_TO_NPM["jquery"] == "jquery"


# ─── Parser ─────────────────────────────────────────────────────────

def _write(tmp, name, content):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


def test_parser_attaches_pkg_and_dedupkey():
    dets = [
        {"component": "moment.js", "version": "2.24.0", "detection": "filecontent", "source": "http://t/moment.js"},
        {"component": "jquery", "version": "3.3.1", "detection": "filename", "source": "http://t/jquery.js"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "retirejs.json", json.dumps(dets))
        cands = rjs_parser.parse(path, Ctx(target_url="http://t/", host="t"))

    by_key = {c.dedup_key: c for c in cands}
    assert by_key["lib:moment.js"].pkg == ("npm", "moment", "2.24.0")
    assert by_key["lib:jquery"].pkg == ("npm", "jquery", "3.3.1")
    assert by_key["lib:jquery"].herramienta_origen == "retire.js"
    # Mismo dedup_key que whatweb → se fusionarán en el merge.
    assert by_key["lib:jquery"].dedup_key == "lib:jquery"


def test_parser_bad_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "retirejs.json", "no-json")
        assert rjs_parser.parse(path, Ctx()) == []


# ─── Integración: retire.js detecta Moment → OSV lo confirma alta ───

def test_retire_then_osv_confirms_high():
    dets = [{"component": "moment.js", "version": "2.24.0", "detection": "filecontent", "source": "http://t/"}]
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "retirejs.json", json.dumps(dets))
        cands = rjs_parser.parse(path, Ctx(target_url="http://t/"))

    # OSV falso: Moment 2.24.0 con un CVE alto (path traversal, 7.5).
    def fake_osv(eco, pkg, ver):
        assert (eco, pkg, ver) == ("npm", "moment", "2.24.0")
        raw = {
            "id": "GHSA-8hfj-j24r-96c4",
            "aliases": ["CVE-2022-24785"],
            "summary": "Path traversal en moment",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "moment"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.29.2"}]}]}],
            "references": [{"url": "https://github.com/moment/moment"}],
        }
        return [osv.normalize(raw, "npm", "moment")]

    enrich_osv(cands, query=fake_osv)
    moment = [c for c in cands if c.dedup_key == "lib:moment.js"][0]
    assert moment.estado == EST_CONFIRMADO
    assert moment.severidad == SEV_ALTA          # 7.5 → alta
    assert moment.cve == "CVE-2022-24785"
    assert "2.29.2" in (moment.recomendacion or "")


def test_unmapped_component_has_no_pkg():
    dets = [{"component": "algo-raro", "version": "1.0.0", "detection": "uri", "source": "http://t/"}]
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "retirejs.json", json.dumps(dets))
        cands = rjs_parser.parse(path, Ctx())
    assert cands[0].pkg is None            # sin mapeo npm → detección info sin OSV
    assert cands[0].severidad == SEV_INFO
