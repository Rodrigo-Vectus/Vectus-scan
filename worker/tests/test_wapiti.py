"""Tests del parser de wapiti (F8c). Sin red: se parsea un wapiti.json fixture
con el formato real (vulnerabilities + classifications)."""
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
            "SQL Injection": {
                "desc": "SQL injection ...",
                "sol": "Usar consultas parametrizadas.",
                "ref": {
                    "OWASP: SQL Injection": "https://owasp.org/sqli",
                    "CWE-89: Improper Neutralization": "https://cwe.mitre.org/89",
                },
                "wstg": ["WSTG-INPV-05"],
            },
            "Command execution": {
                "desc": "...",
                "sol": "Evitar exec con entrada del usuario.",
                "ref": {"CWE-78: OS Command Injection": "https://cwe.mitre.org/78"},
            },
            "Reflected Cross Site Scripting": {
                "desc": "...", "sol": "Escapar la salida.",
                "ref": {"CWE-79: XSS": "https://cwe.mitre.org/79"},
            },
        },
        "vulnerabilities": {
            "SQL Injection": [
                {"method": "GET", "path": "/page", "info": "SQL Injection via id",
                 "level": 3, "parameter": "id", "module": "sql",
                 "http_request": "GET /page?id=1%27 HTTP/1.1"},
            ],
            "Command execution": [
                {"method": "POST", "path": "/run", "info": "Command exec via cmd",
                 "level": 4, "parameter": "cmd", "module": "exec",
                 "http_request": "POST /run HTTP/1.1"},
            ],
            "Reflected Cross Site Scripting": [
                {"method": "GET", "path": "/s", "info": "XSS via q",
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


def test_parses_levels_and_cwe():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, _report())
        cands = wapiti.parse(path, Ctx(target_url="http://t/", host="t"))

    by_key = {c.dedup_key: c for c in cands}
    sqli = by_key["wapiti:sql injection:/page:id"]
    assert sqli.severidad == SEV_ALTA           # level 3
    assert sqli.estado == EST_CONFIRMADO
    assert sqli.cwe == "CWE-89"
    assert sqli.herramienta_origen == "wapiti"
    assert "parametrizadas" in sqli.recomendacion

    exe = by_key["wapiti:command execution:/run:cmd"]
    assert exe.severidad == SEV_CRITICA         # level 4
    assert exe.cwe == "CWE-78"

    xss = by_key["wapiti:reflected cross site scripting:/s:q"]
    assert xss.severidad == SEV_MEDIA           # level 2
    assert xss.cwe == "CWE-79"


def test_empty_category_ignored():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, _report())
        cands = wapiti.parse(path, Ctx())
    assert all("empty category" not in c.dedup_key for c in cands)
    assert len(cands) == 3  # solo las 3 categorías con hallazgos


def test_title_includes_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, _report())
        cands = wapiti.parse(path, Ctx())
    sqli = [c for c in cands if c.dedup_key.startswith("wapiti:sql")][0]
    assert "id" in sqli.titulo and "SQL Injection" in sqli.titulo


def test_bad_file_is_safe():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "wapiti.json")
        open(p, "w").write("no-json")
        assert wapiti.parse(p, Ctx()) == []


def test_no_vulnerabilities_key():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, {"infos": {"target": "http://t/"}})
        assert wapiti.parse(path, Ctx()) == []
