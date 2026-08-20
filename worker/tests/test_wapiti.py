"""Tests del parser de wapiti (F8c) + localización al español (F8d)."""
import json
import os
import tempfile

from worker.parsers import wapiti
from worker.parsers import (
    Ctx,
    EST_CONFIRMADO,
    SEV_ALTA,
    SEV_CRITICA,
    SEV_MEDIA,
)


def _report():
    return {
        "classifications": {
            "SQL Injection": {"desc": "...", "sol": "...",
                              "ref": {"CWE-89: ...": "https://cwe.mitre.org/89"}},
            "Command execution": {"desc": "...", "sol": "...",
                                  "ref": {"CWE-78: ...": "https://cwe.mitre.org/78"}},
            "Reflected Cross Site Scripting": {"desc": "...", "sol": "...",
                                               "ref": {"CWE-79: ...": "https://cwe.mitre.org/79"}},
        },
        "vulnerabilities": {
            "SQL Injection": [
                {"method": "GET", "path": "/page", "info": "SQL Injection via id",
                 "level": 3, "parameter": "id", "module": "sql",
                 "http_request": "GET /page?id=1%27 HTTP/1.1"},
            ],
            "Command execution": [
                {"method": "POST", "path": "/run", "info": "exec via cmd",
                 "level": 4, "parameter": "cmd", "module": "exec", "http_request": ""},
            ],
            "Reflected Cross Site Scripting": [
                {"method": "GET", "path": "/s", "info": "xss via q",
                 "level": 2, "parameter": "q", "module": "xss", "http_request": ""},
            ],
            "Empty Category": [],
        },
        "infos": {"target": "http://t/", "version": "3.3.2"},
    }


def _write(tmp, data):
    p = os.path.join(tmp, "wapiti.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return p


def test_localized_titles_and_slugs():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, _report())
        cands = wapiti.parse(path, Ctx(target_url="http://t/", host="t"))

    by_key = {c.dedup_key: c for c in cands}
    sqli = by_key["wapiti:sqli:/page:id"]
    assert sqli.severidad == SEV_ALTA
    assert sqli.estado == EST_CONFIRMADO
    assert sqli.cwe == "CWE-89"
    assert sqli.titulo == "Inyección SQL (parámetro 'id')"   # español
    assert "wapiti" in sqli.evidencia and "inyección SQL" in sqli.evidencia

    exe = by_key["wapiti:exec:/run:cmd"]
    assert exe.severidad == SEV_CRITICA
    assert exe.titulo.startswith("Ejecución de comandos")

    xss = by_key["wapiti:xss:/s:q"]
    assert xss.severidad == SEV_MEDIA
    assert "Cross-Site Scripting" in xss.titulo


def test_empty_category_ignored():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, _report())
        cands = wapiti.parse(path, Ctx())
    assert len(cands) == 3
    assert all("empty" not in c.dedup_key for c in cands)


def test_unknown_category_fallback_slug():
    data = {
        "classifications": {},
        "vulnerabilities": {"Weird New Thing": [
            {"method": "GET", "path": "/x", "info": "y", "level": 1,
             "parameter": "p", "module": "zz"}]},
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, data)
        cands = wapiti.parse(path, Ctx())
    # slug derivado del nombre; título cae al inglés como último recurso.
    assert cands[0].dedup_key == "wapiti:weird-new-thing:/x:p"


def test_bad_file_is_safe():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "wapiti.json")
        open(p, "w").write("no-json")
        assert wapiti.parse(p, Ctx()) == []
