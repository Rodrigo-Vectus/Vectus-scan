"""nmap --script ssl-enum-ciphers,ssl-cert → TLS (B.3).

Parsea el texto del `output` del script (más robusto que las tablas anidadas):
- TLS 1.0/1.1 o SSLv3 habilitados → hallazgo. Solo 1.2/1.3 → positivo.
- `least strength` con nota distinta de A → hallazgo. Solo A → positivo.
Forward secrecy fino y datos del certificado se afinan en F3b.
"""
import re

from worker.parsers import (
    SEV_MEDIA,
    SEV_BAJA,
    EST_CONFIRMADO,
    EST_POSITIVO,
    FindingCandidate,
)

try:
    from defusedxml.ElementTree import parse as _parse
except Exception:  # pragma: no cover
    from xml.etree.ElementTree import parse as _parse

_OBSOLETOS = ["SSLv3", "TLSv1.0", "TLSv1.1"]


def _script_output(root) -> str:
    chunks = []
    for script in root.iter("script"):
        if script.get("id") in ("ssl-enum-ciphers", "ssl-cert"):
            chunks.append(script.get("output") or "")
    return "\n".join(chunks)


def parse(path: str, ctx) -> list[FindingCandidate]:
    try:
        root = _parse(path).getroot()
    except Exception:
        return []
    text = _script_output(root)
    if not text.strip():
        return []

    out: list[FindingCandidate] = []
    sistema = f"{ctx.host}:443"

    presentes = [p for p in _OBSOLETOS if re.search(rf"{re.escape(p)}\s*:", text)]
    if presentes:
        out.append(
            FindingCandidate(
                titulo="Protocolos TLS obsoletos habilitados",
                severidad=SEV_MEDIA,
                estado=EST_CONFIRMADO,
                herramienta_origen="nmap",
                sistema_afectado=sistema,
                evidencia="Habilitados: " + ", ".join(presentes),
                cwe="CWE-327",
                recomendacion="Deshabilitar SSLv3/TLS 1.0/1.1; permitir solo TLS 1.2 y 1.3.",
                mas_info="https://datatracker.ietf.org/doc/html/rfc8996",
                dedup_key="tls:obsoletos",
            )
        )
    elif re.search(r"TLSv1\.[23]\s*:", text):
        out.append(
            FindingCandidate(
                titulo="Solo TLS 1.2/1.3 habilitado",
                severidad=SEV_BAJA,
                estado=EST_POSITIVO,
                herramienta_origen="nmap",
                sistema_afectado=sistema,
                evidencia="No se detectaron SSLv3/TLS 1.0/1.1.",
                recomendacion="Buena postura: mantener solo protocolos TLS modernos.",
                dedup_key="tls:solo-modernos",
            )
        )

    m = re.search(r"least strength:\s*([A-F])", text)
    if m:
        grado = m.group(1)
        if grado == "A":
            out.append(
                FindingCandidate(
                    titulo="Fuerza de cifrado TLS adecuada (least strength A)",
                    severidad=SEV_BAJA,
                    estado=EST_POSITIVO,
                    herramienta_origen="nmap",
                    sistema_afectado=sistema,
                    evidencia="least strength: A",
                    recomendacion="Buena postura: suite de cifrado robusta.",
                    dedup_key="tls:least-strength",
                )
            )
        else:
            out.append(
                FindingCandidate(
                    titulo=f"Cifrados TLS débiles (least strength {grado})",
                    severidad=SEV_MEDIA if grado in ("D", "E", "F") else SEV_BAJA,
                    estado=EST_CONFIRMADO,
                    herramienta_origen="nmap",
                    sistema_afectado=sistema,
                    evidencia=f"least strength: {grado}",
                    cwe="CWE-326",
                    recomendacion="Retirar cifrados débiles; preferir AEAD (AES-GCM/ChaCha20) con ECDHE.",
                    dedup_key="tls:least-strength",
                )
            )
    return out
