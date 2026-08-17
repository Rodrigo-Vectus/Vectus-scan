"""nmap -sV -oX → puertos/servicios (B.3).

Registro de reconocimiento (severidad info): puertos abiertos, servicio y
banner de versión. `tcpwrapped` no es vulnerabilidad: indica filtrado que
corta el banner. Los banners de versión alimentan la correlación de CVE en
F3b; acá se guardan como contexto.
"""
from worker.parsers import (
    SEV_INFO,
    EST_CONFIRMADO,
    EST_A_VALIDAR,
    FindingCandidate,
    version_review,
)

# Patrones de rDNS/PTR que delatan un CDN/edge (no el origen real).
_CDN_HINTS = (
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva",
    "sucuri", "stackpath", "edgecast", "azureedge", "cdn77", "keycdn",
    "bunnycdn", "gcore", "llnwd", "cdn",
)


def _cdn_origin_finding(root, ctx) -> FindingCandidate | None:
    """Interpreta CDN vs origen a partir de la IP y el PTR del XML (B.5)."""
    ip = None
    ptr = None
    for host in root.iter("host"):
        for addr in host.iter("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
        for hn in host.iter("hostname"):
            if hn.get("type") == "PTR":
                ptr = hn.get("name")
        if ip or ptr:
            break
    if not ip and not ptr:
        return None

    hay_cdn = ptr and any(h in ptr.lower() for h in _CDN_HINTS)
    if hay_cdn:
        return FindingCandidate(
            titulo="Objetivo detrás de CDN/edge",
            severidad=SEV_INFO,
            estado=EST_A_VALIDAR,
            herramienta_origen="nmap",
            sistema_afectado=ip or ctx.host,
            evidencia=f"IP {ip or '?'} · PTR {ptr}: parece un CDN/edge.",
            recomendacion="El barrido evalúa el edge, no el origen. Identificar y validar el origen real por separado.",
            dedup_key="contexto:cdn-origen",
        )
    return FindingCandidate(
        titulo="Objetivo resuelve a hosting/origen (no CDN)",
        severidad=SEV_INFO,
        estado=EST_CONFIRMADO,
        herramienta_origen="nmap",
        sistema_afectado=ip or ctx.host,
        evidencia=f"IP {ip or '?'}" + (f" · PTR {ptr}" if ptr else " · sin PTR"),
        recomendacion="El barrido evalúa el origen real (servicios expuestos directamente).",
        dedup_key="contexto:cdn-origen",
    )

try:
    from defusedxml.ElementTree import parse as _parse
except Exception:  # pragma: no cover - fallback si defusedxml no está
    from xml.etree.ElementTree import parse as _parse


def parse(path: str, ctx) -> list[FindingCandidate]:
    try:
        root = _parse(path).getroot()
    except Exception:
        return []

    out: list[FindingCandidate] = []
    cdn = _cdn_origin_finding(root, ctx)
    if cdn is not None:
        out.append(cdn)
    for host in root.iter("host"):
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "?")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = (svc.get("name") if svc is not None else "") or "desconocido"

            if name == "tcpwrapped":
                out.append(
                    FindingCandidate(
                        titulo=f"Puerto {portid}/{proto}: servicio filtrado (tcpwrapped)",
                        severidad=SEV_INFO,
                        estado=EST_CONFIRMADO,
                        herramienta_origen="nmap",
                        sistema_afectado=f"{ctx.host}:{portid}",
                        evidencia="nmap reporta tcpwrapped: el filtrado corta el banner del servicio.",
                        recomendacion="No es una vulnerabilidad. Indica firewall/filtrado; impide fingerprint de versión.",
                        dedup_key=f"nmap:tcpwrapped:{portid}",
                    )
                )
                continue

            product = (svc.get("product") if svc is not None else "") or ""
            version = (svc.get("version") if svc is not None else "") or ""
            banner = " ".join(x for x in (product, version) if x).strip()
            detalle = f"{name}" + (f" ({banner})" if banner else "")
            out.append(
                FindingCandidate(
                    titulo=f"Puerto {portid}/{proto} abierto: {detalle}",
                    severidad=SEV_INFO,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="nmap",
                    sistema_afectado=f"{ctx.host}:{portid}",
                    evidencia=f"nmap: puerto {portid}/{proto} open, servicio {detalle}",
                    recomendacion="Verificar que el servicio expuesto sea necesario y esté actualizado.",
                    dedup_key=f"nmap:port:{portid}",
                )
            )
            # Correlación CVE-por-versión (B.8): solo si hay versión numérica.
            if version and any(c.isdigit() for c in version):
                out.append(
                    version_review(product, version, "nmap", f"{ctx.host}:{portid}")
                )
    return out
