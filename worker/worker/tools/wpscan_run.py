"""Ejecutor de WPScan con gate por CMS (F8e).

WPScan enumera el core de WordPress, sus **plugins y temas** y cruza las
versiones con la base de vulnerabilidades (CVEs) — ahí están la mayoría de las
altas/críticas de un WordPress. Es enumeración (detección no intrusiva); **no**
se activa la fuerza bruta de contraseñas.

Para no malgastar tiempo ni el cupo del token en sitios que no son WordPress,
este wrapper **gatea** por la detección de whatweb (etapa de reconocimiento):
solo corre WPScan si el sitio parece WordPress.

Se ejecuta como subproceso (encaja en el modelo ToolSpec):
    python -m worker.tools.wpscan_run <url> -o <out.json> [--scan-dir DIR] [--ua UA]

Token: se lee de la variable de entorno WPSCAN_API_TOKEN (del `.env` del
server). Sin token, WPScan enumera pero no trae los CVEs; el wrapper igual
corre y degrada. Ante cualquier error, escribe un marcador y sale 0 para no
romper el scan.
"""
import argparse
import glob
import json
import os
import subprocess
import sys

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


def _is_wordpress(scan_dir: str) -> bool:
    """True si algún whatweb.json del scan detectó WordPress."""
    for path in glob.glob(os.path.join(scan_dir, "*", "whatweb.json")) + \
            glob.glob(os.path.join(scan_dir, "whatweb.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        entries = data if isinstance(data, list) else [data]
        for e in entries:
            plugins = (e or {}).get("plugins") or {}
            if any(k.lower() == "wordpress" for k in plugins):
                return True
    return False


def _write(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="wpscan_run")
    ap.add_argument("url")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--scan-dir", default=None,
                    help="raíz del scan (por defecto: 2 niveles arriba de -o)")
    ap.add_argument("--ua", default=_DEFAULT_UA)
    ap.add_argument("--timeout", type=int, default=540)
    args = ap.parse_args(argv)

    scan_dir = args.scan_dir or os.path.dirname(os.path.dirname(args.output))

    # Gate: solo WordPress.
    if not _is_wordpress(scan_dir):
        _write(args.output, {"gated": "not_wordpress"})
        sys.stderr.write("wpscan: sitio no WordPress según whatweb; se omite.\n")
        return 0

    token = os.getenv("WPSCAN_API_TOKEN", "").strip()
    cmd = [
        "wpscan", "--url", args.url,
        "--format", "json", "--output", args.output,
        "--no-banner", "--disable-tls-checks", "--force",
        "--random-user-agent",
        "--enumerate", "vp,vt,cb,dbe",
        "--plugins-detection", "passive",
        "--request-timeout", "60", "--max-threads", "5",
    ]
    if token:
        cmd += ["--api-token", token]
    else:
        sys.stderr.write("wpscan: sin WPSCAN_API_TOKEN; enumera sin CVEs.\n")

    try:
        # WPScan devuelve exit!=0 cuando encuentra vulns (p. ej. 5); no es error.
        subprocess.run(cmd, capture_output=True, timeout=args.timeout + 30)
    except subprocess.TimeoutExpired:
        sys.stderr.write("wpscan: timeout.\n")
    except (FileNotFoundError, OSError) as exc:
        sys.stderr.write(f"wpscan: no se pudo ejecutar ({exc}).\n")

    # Si WPScan no dejó un JSON válido, escribir un marcador para que el parser
    # no rompa.
    try:
        with open(args.output, "r", encoding="utf-8") as f:
            json.load(f)
    except (OSError, ValueError):
        _write(args.output, {"error": "wpscan sin salida válida"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
