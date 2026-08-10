"""Constructores de comandos del BIEC.

Cada herramienta se describe como un `ToolSpec` con su lista de argumentos
(argv) — nunca una string de shell — y la ruta de su salida cruda. Estas
funciones son puras (no ejecutan nada), por eso se pueden testear afirmando
el argv exacto sin tener las herramientas instaladas.

El mapeo etapa→herramientas sigue el brief:
  1 reconocimiento : nmap (servicios), whatweb, dig, whois
  2 enumeracion    : subfinder (pasivo, solo contexto)
  3 descubrimiento : ffuf (wordlist curada)
  4 vulnerabilidades: nuclei, nikto
  5 configuracion  : curl (headers), nmap (ssl-enum-ciphers)
"""
import os
from dataclasses import dataclass

from worker.target import Target

# Wordlist curada que trae el paquete `dirb` (instalada en la imagen del
# worker). Se prefiere una lista acotada por rendimiento y por firewall (B.7).
WORDLIST = "/usr/share/dirb/wordlists/common.txt"


@dataclass
class ToolSpec:
    name: str
    argv: list[str]
    output_path: str
    capture_stdout: bool  # True: el runner vuelca stdout al output_path
    timeout: int


def _p(out_dir: str, filename: str) -> str:
    return os.path.join(out_dir, filename)


def _reconocimiento(tgt: Target, out_dir: str) -> list[ToolSpec]:
    return [
        ToolSpec(
            "nmap_services",
            ["nmap", "-sV", "-Pn", "-T3", "-oX", _p(out_dir, "nmap_services.xml"), tgt.host],
            _p(out_dir, "nmap_services.xml"),
            False,
            300,
        ),
        ToolSpec(
            "whatweb",
            ["whatweb", "-a", "1", "--log-json", _p(out_dir, "whatweb.json"), "--no-errors", tgt.url],
            _p(out_dir, "whatweb.json"),
            False,
            120,
        ),
        ToolSpec(
            "dig",
            ["dig", tgt.host, "A", "AAAA", "CNAME", "+noall", "+answer"],
            _p(out_dir, "dig.txt"),
            True,
            30,
        ),
        ToolSpec(
            "whois",
            ["whois", tgt.host],
            _p(out_dir, "whois.txt"),
            True,
            30,
        ),
    ]


def _enumeracion(tgt: Target, out_dir: str) -> list[ToolSpec]:
    # subfinder pasivo: enumera subdominios SOLO como contexto. El motor no
    # dispara ninguna herramienta contra los subdominios hallados (B.6).
    return [
        ToolSpec(
            "subfinder",
            ["subfinder", "-d", tgt.host, "-silent", "-o", _p(out_dir, "subfinder.txt")],
            _p(out_dir, "subfinder.txt"),
            False,
            120,
        ),
    ]


def _descubrimiento(tgt: Target, out_dir: str) -> list[ToolSpec]:
    return [
        ToolSpec(
            "ffuf",
            [
                "ffuf", "-u", f"{tgt.url}/FUZZ", "-w", WORDLIST,
                "-of", "json", "-o", _p(out_dir, "ffuf.json"),
                "-t", "20", "-rate", "50", "-s",
            ],
            _p(out_dir, "ffuf.json"),
            False,
            600,
        ),
    ]


def _vulnerabilidades(tgt: Target, out_dir: str) -> list[ToolSpec]:
    return [
        ToolSpec(
            "nuclei",
            [
                "nuclei", "-u", tgt.url, "-jsonl", "-o", _p(out_dir, "nuclei.jsonl"),
                "-no-interactsh", "-rl", "50", "-c", "20",
            ],
            _p(out_dir, "nuclei.jsonl"),
            False,
            900,
        ),
        ToolSpec(
            "nikto",
            ["nikto", "-h", tgt.url, "-o", _p(out_dir, "nikto.txt"), "-Format", "txt", "-maxtime", "300s"],
            _p(out_dir, "nikto.txt"),
            False,
            400,
        ),
    ]


def _configuracion(tgt: Target, out_dir: str) -> list[ToolSpec]:
    return [
        ToolSpec(
            "curl_headers",
            ["curl", "-sSIL", "--compressed", "--max-time", "30", tgt.url],
            _p(out_dir, "headers.txt"),
            True,
            60,
        ),
        ToolSpec(
            "nmap_tls",
            [
                "nmap", "-Pn", "-p", "443", "--script", "ssl-enum-ciphers,ssl-cert",
                "-oX", _p(out_dir, "nmap_tls.xml"), tgt.host,
            ],
            _p(out_dir, "nmap_tls.xml"),
            False,
            300,
        ),
    ]


_BUILDERS = {
    "reconocimiento": _reconocimiento,
    "enumeracion": _enumeracion,
    "descubrimiento": _descubrimiento,
    "vulnerabilidades": _vulnerabilidades,
    "configuracion": _configuracion,
}

STAGE_KEYS = list(_BUILDERS.keys())


def build_stage_specs(stage_key: str, tgt: Target, out_dir: str) -> list[ToolSpec]:
    builder = _BUILDERS.get(stage_key)
    if builder is None:
        raise ValueError(f"etapa desconocida: {stage_key}")
    return builder(tgt, out_dir)
