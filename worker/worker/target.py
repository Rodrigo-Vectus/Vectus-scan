import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

# Hostname válido: etiquetas alfanuméricas con guiones internos, separadas por
# puntos. No permite empezar con '-' (evita que un target se interprete como
# flag de una herramienta) ni caracteres raros (evita inyección de argumentos).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


@dataclass(frozen=True)
class Target:
    raw: str
    scheme: str
    host: str
    port: int | None
    url: str  # base normalizada, sin path (ej. https://ejemplo.com)


def _valid_host(host: str) -> bool:
    if not host or host.startswith("-"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(host))


def parse_target(raw: str) -> Target:
    """Convierte un target de usuario en componentes validados.

    Acepta 'https://host[:puerto]', 'http://...' o un host pelado (asume https).
    Lanza ValueError si el host no es un hostname/IP válido. Como todos los
    comandos se arman con listas de argumentos (nunca con shell), esto es una
    defensa adicional, no la única.
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("target vacío")

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"esquema no soportado: {scheme}")

    host = parsed.hostname or ""
    if not _valid_host(host):
        raise ValueError(f"host inválido: {host!r}")

    port = parsed.port
    netloc = host if port is None else f"{host}:{port}"
    url = f"{scheme}://{netloc}"

    return Target(raw=raw, scheme=scheme, host=host, port=port, url=url)
