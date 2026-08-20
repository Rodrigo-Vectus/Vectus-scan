"""Detector de librerías JS al estilo retire.js, en Python puro (F8b, opción B).

Usa las **firmas oficiales de retire.js** (`jsrepository.json`, bundleado en la
imagen) para identificar librería + versión por:
  - **uri**: regex sobre la URL del `<script src>`.
  - **filename**: regex sobre el nombre de archivo del script.
  - **filecontent**: regex sobre el contenido del JS (y del HTML, para libs
    embebidas inline).

No ejecuta las firmas tipo `func` (requieren un motor JS). Detecta y reporta;
**no valida** vulnerabilidad: de eso se encarga el enriquecedor OSV (F8a), que
consume la pista `pkg` que produce el parser `retirejs`.

CLI (encaja en el modelo ToolSpec del worker, se corre como subprocess):
    python -m worker.tools.retirejs <url> -o <salida.json> [--repo PATH] [--ua UA]

Baja el HTML del **target autorizado** y sus scripts (mismo objetivo; con UA de
navegador y throttling). Ante cualquier error de red, degrada: escribe lo que
pudo y sale 0.
"""
import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.request
from html.parser import HTMLParser
from urllib.error import URLError
from urllib.parse import urljoin

DEFAULT_REPO = os.getenv("RETIREJS_REPO", "/opt/retirejs/jsrepository.json")

# retire.js reemplaza §§version§§ por este regex de versión.
_VERSION_RE = r"[0-9][0-9.a-z_\-]+"

# Componente de retire.js → paquete npm (para validar CVEs vía OSV). Solo los
# que mapean con confianza; el resto se reporta como detección (info) sin pkg.
RETIRE_TO_NPM = {
    "jquery": "jquery",
    "jquery-ui": "jquery-ui",
    "jquery-ui-dialog": "jquery-ui",
    "moment.js": "moment",
    "bootstrap": "bootstrap",
    "angularjs": "angular",
    "vue": "vue",
    "react": "react",
    "lodash": "lodash",
    "underscore.js": "underscore",
    "backbone.js": "backbone",
    "knockout": "knockout",
    "dojo": "dojo",
    "d3": "d3",
    "axios": "axios",
    "mustache.js": "mustache",
    "handlebars": "handlebars",
}

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


# ─── Firmas ─────────────────────────────────────────────────────────

def load_repo(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _compile(pattern: str):
    """Compila un patrón de retire (con §§version§§) a regex con grupo de
    versión. Devuelve None si no compila."""
    try:
        return re.compile(pattern.replace("§§version§§", _VERSION_RE))
    except re.error:
        return None


def compile_signatures(repo: dict) -> list[tuple]:
    """(componente, tipo, regex_compilada) para uri/filename/filecontent."""
    sigs = []
    for comp, spec in repo.items():
        extractors = spec.get("extractors") or {}
        for kind in ("uri", "filename", "filecontent"):
            for pat in extractors.get(kind) or []:
                rx = _compile(pat)
                if rx is not None:
                    sigs.append((comp, kind, rx))
    return sigs


_VERSION_SUFFIX_RE = re.compile(r"(?:[.\-](?:min|js))+$", re.IGNORECASE)


def _clean_version(v: str) -> str:
    """Recorta sufijos de archivo que el regex greedy puede arrastrar
    (`3.3.1.min` → `3.3.1`), sin tocar sufijos de versión legítimos
    (`1.0.0-beta` queda igual)."""
    return _VERSION_SUFFIX_RE.sub("", v.strip().strip("."))


def _match(text: str, sigs, kinds: tuple) -> list[tuple]:
    """Devuelve [(componente, version, tipo)] para las firmas que matcheen."""
    out = []
    for comp, kind, rx in sigs:
        if kind not in kinds:
            continue
        m = rx.search(text)
        if m and m.groups():
            version = _clean_version(m.group(1))
            if version:
                out.append((comp, version, kind))
    return out


def detect_in_url(url: str, sigs) -> list[tuple]:
    fname = url.split("?")[0].rsplit("/", 1)[-1]
    hits = _match(url, sigs, ("uri",))
    hits += _match(fname, sigs, ("filename",))
    return hits


def detect_in_content(content: str, sigs) -> list[tuple]:
    return _match(content, sigs, ("filecontent",))


# ─── Descarga (CLI) ─────────────────────────────────────────────────

class _ScriptSrc(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            for k, v in attrs:
                if k.lower() == "src" and v:
                    self.srcs.append(v)


def _ssl_ctx() -> ssl.SSLContext:
    """Contexto SSL que NO verifica el certificado del objetivo (fallback urllib)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _curl(args: list[str], timeout: int) -> tuple[int, bytes]:
    """Corre curl y devuelve (returncode, stdout). curl ya está en la imagen
    del worker y negocia TLS con servidores viejos que el `ssl` de Python
    rechaza (SSLV3_ALERT_HANDSHAKE_FAILURE, ciphers/versión restringidos)."""
    try:
        p = subprocess.run(
            ["curl", *args], capture_output=True, timeout=timeout + 5
        )
        return p.returncode, p.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return 1, b""


def _fetch(url: str, ua: str, timeout: int, max_bytes: int) -> str | None:
    """Baja el contenido de `url`. Primario: curl (-L sigue redirects, -k
    tolera el cert del target). Fallback: urllib. Devuelve texto o None."""
    rc, out = _curl(
        [
            "-sL", "-k", "--max-time", str(timeout),
            "--max-filesize", str(max_bytes),
            "-A", ua, url,
        ],
        timeout,
    )
    if rc == 0 and out:
        return out.decode("utf-8", errors="replace")

    # Fallback urllib (por si curl no estuviera disponible).
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            return resp.read(max_bytes).decode("utf-8", errors="replace")
    except (URLError, TimeoutError, OSError, ValueError):
        return None


def _resolve_final_url(url: str, ua: str, timeout: int) -> str:
    """URL final tras redirects, vía curl (`-o /dev/null -w %{url_effective}`).
    Ante error, vuelve la original."""
    rc, out = _curl(
        [
            "-sL", "-k", "--max-time", str(timeout), "-A", ua,
            "-o", "/dev/null", "-w", "%{url_effective}", url,
        ],
        timeout,
    )
    if rc == 0 and out:
        final = out.decode("utf-8", errors="replace").strip()
        if final:
            return final
    return url


def scan(
    url: str,
    repo: dict,
    fetch=None,
    ua: str = _DEFAULT_UA,
    timeout: int = 10,
    max_scripts: int = 40,
    max_bytes: int = 2_000_000,
    throttle: float = 0.1,
    debug=None,
) -> list[dict]:
    """Detecta librerías en `url`. `fetch(u)->str|None` es inyectable (tests).

    En modo real (fetch=None) sigue redirects para partir de la URL final
    (muchos sitios hacen 302 a otro host/https) y usa esa como base para
    resolver los `<script src>` relativos.
    """
    if fetch is None:
        base = _resolve_final_url(url, ua, timeout)

        def fetch(u):
            return _fetch(u, ua, timeout, max_bytes)
    else:
        base = url  # en tests la base es la URL dada

    def log(msg):
        if debug:
            debug(msg)

    sigs = compile_signatures(repo)
    detections: dict[tuple, dict] = {}

    def add(comp, version, kind, source):
        detections.setdefault((comp, version), {
            "component": comp, "version": version,
            "detection": kind, "source": source,
        })

    if base != url:
        log(f"redirect: {url} -> {base}")
    html = fetch(base)
    if html is None:
        log(f"no se pudo bajar el HTML de {base}")
        return []
    log(f"html {len(html)} bytes")

    # Firmas de contenido sobre el HTML (libs embebidas inline).
    for comp, ver, kind in detect_in_content(html, sigs):
        add(comp, ver, "filecontent", base)

    parser = _ScriptSrc()
    try:
        parser.feed(html)
    except Exception:
        pass
    log(f"{len(parser.srcs)} scripts en el HTML")

    count = 0
    for src in parser.srcs:
        if count >= max_scripts:
            break
        full = urljoin(base, src)
        # 1) por URL/filename (no requiere descargar).
        for comp, ver, kind in detect_in_url(full, sigs):
            add(comp, ver, kind, full)
        # 2) por contenido (descarga el JS).
        count += 1
        body = fetch(full)
        if body:
            for comp, ver, kind in detect_in_content(body, sigs):
                add(comp, ver, "filecontent", full)
        if throttle:
            time.sleep(throttle)

    log(f"{len(detections)} detecciones")
    return list(detections.values())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="retirejs")
    ap.add_argument("url")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--ua", default=_DEFAULT_UA)
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args(argv)

    detections: list[dict] = []
    try:
        repo = load_repo(args.repo)
        detections = scan(
            args.url, repo, ua=args.ua, timeout=args.timeout,
            debug=lambda m: sys.stderr.write(f"retirejs: {m}\n"),
        )
    except Exception as exc:  # noqa: BLE001 — degradar, no romper el scan
        sys.stderr.write(f"retirejs: {exc}\n")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(detections, f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
