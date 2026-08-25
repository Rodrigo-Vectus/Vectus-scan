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

# Módulos de wapiti para la etapa de aplicación (F8c). Detección activa NO
# intrusiva: envían payloads de prueba para *detectar* SQLi/XSS/inyección/
# traversal/SSRF/XXE/etc. y observan la respuesta. NO explotan. Se excluyen a
# propósito los módulos de fuerza bruta (brute_login_form) y los que solaparían
# con lo que ya hacen curl_headers/nmap_tls (http_headers, csp, cookieflags,
# ssl). Es el set que da mejores resultados manteniendo el principio rector.
WAPITI_MODULES = (
    "sql,xss,permanentxss,exec,file,crlf,ssrf,xxe,redirect,"
    "htaccess,backup,ldap,log4shell,spring4shell,shellshock,upload,methods"
)

# User-Agent de navegador real. Muchos WAF/CDN cortan el UA por defecto de las
# herramientas (curl/whatweb/nikto), devolviendo bloqueos o nada. Con un UA de
# navegador se obtienen cabeceras y respuestas reales, lo que además habilita
# el contraste nikto↔curl (B.10). No cambia el alcance: sigue siendo el target
# autorizado; solo mejora la fidelidad de la respuesta.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


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
            ["whatweb", "-a", "1", "--log-json", _p(out_dir, "whatweb.json"), "--no-errors", "-U", USER_AGENT, tgt.url],
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
                "-H", f"User-Agent: {USER_AGENT}",
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
                "-timeout", "10", "-retries", "1",
                "-H", f"User-Agent: {USER_AGENT}",
            ],
            _p(out_dir, "nuclei.jsonl"),
            False,
            900,
        ),
        ToolSpec(
            "nikto",
            ["nikto", "-h", tgt.url, "-o", _p(out_dir, "nikto.txt"), "-Format", "txt", "-maxtime", "300s", "-useragent", USER_AGENT],
            _p(out_dir, "nikto.txt"),
            False,
            360,
        ),
        # retire.js (detector propio en Python, F8b): identifica librerías JS
        # cliente + versión por firmas oficiales de retire.js. Su salida
        # alimenta la validación OSV (F8a) para confirmar CVEs. Baja el HTML y
        # los scripts del target autorizado (mismo objetivo; UA de navegador y
        # throttling). Degrada elegante ante errores de red.
        ToolSpec(
            "retirejs",
            ["python", "-m", "worker.tools.retirejs", tgt.url, "-o", _p(out_dir, "retirejs.json"), "--ua", USER_AGENT],
            _p(out_dir, "retirejs.json"),
            False,
            180,
        ),
    ]


def _aplicacion(tgt: Target, out_dir: str) -> list[ToolSpec]:
    # Detección activa de vulnerabilidades de aplicación (wapiti). Acotada por
    # rendimiento y firewall: crawl de profundidad 2, tope de links por página,
    # y un techo de tiempo global (`--max-scan-time`). `--verify-ssl 0` evita el
    # problema de handshake TLS con servidores viejos. `--scope folder` mantiene
    # el barrido dentro de la carpeta del objetivo autorizado.
    return [
        ToolSpec(
            "wapiti",
            [
                "wapiti", "-u", tgt.url,
                "-m", WAPITI_MODULES,
                "--scope", "folder",
                "-d", "2",
                "--max-links-per-page", "20",
                "--max-files-per-dir", "10",
                "--max-scan-time", "480",
                "-t", "10",
                "-A", USER_AGENT,
                "--verify-ssl", "0",
                "--flush-session",
                "--store-session", out_dir,
                "-f", "json", "-o", _p(out_dir, "wapiti.json"),
            ],
            _p(out_dir, "wapiti.json"),
            False,
            660,  # margen sobre max-scan-time (480) para crawl + reporte
        ),
    ]


def _cms(tgt: Target, out_dir: str) -> list[ToolSpec]:
    # Análisis de CMS (F8e). WPScan enumera core/plugins/temas de WordPress y
    # cruza versiones con la base de vulnerabilidades. El wrapper gatea por la
    # detección de whatweb: si el sitio no es WordPress, no corre WPScan (no
    # gasta tiempo ni cupo del token). Solo enumeración; sin fuerza bruta.
    return [
        ToolSpec(
            "wpscan",
            [
                "python", "-m", "worker.tools.wpscan_run", tgt.url,
                "-o", _p(out_dir, "wpscan.json"),
                "--scan-dir", os.path.dirname(out_dir),
                "--ua", USER_AGENT,
            ],
            _p(out_dir, "wpscan.json"),
            False,
            600,
        ),
    ]


def _configuracion(tgt: Target, out_dir: str) -> list[ToolSpec]:
    return [
        ToolSpec(
            "curl_headers",
            ["curl", "-sSL", "-D", "-", "-o", "/dev/null", "--compressed", "--max-time", "30", "-A", USER_AGENT, tgt.url],
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
    "aplicacion": _aplicacion,
    "cms": _cms,
    "configuracion": _configuracion,
}

STAGE_KEYS = list(_BUILDERS.keys())


def build_stage_specs(stage_key: str, tgt: Target, out_dir: str) -> list[ToolSpec]:
    builder = _BUILDERS.get(stage_key)
    if builder is None:
        raise ValueError(f"etapa desconocida: {stage_key}")
    return builder(tgt, out_dir)
