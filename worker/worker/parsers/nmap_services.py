"""nmap -sV -oX → puertos/servicios (B.3).

Registro de reconocimiento (severidad info): puertos abiertos, servicio y
banner de versión. `tcpwrapped` no es vulnerabilidad: indica filtrado que
corta el banner. Los banners de versión alimentan la correlación de CVE en
F3b; acá se guardan como contexto.
"""
from worker.parsers import SEV_INFO, EST_CONFIRMADO, FindingCandidate

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
    return out
