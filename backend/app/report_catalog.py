"""Catálogo curado de hallazgos para el informe (F4c).

Cada tipo de hallazgo del BIEC tiene una ficha profesional: descripción
técnica, desglose CVSS 3.1 (con las etiquetas en español que usa la plantilla),
recomendación para el equipo técnico y referencias. Al generar el informe, se
enriquece cada vulnerabilidad con su ficha; si no hay ficha (p. ej. hallazgos
de nuclei arbitrarios), se usan los datos propios del hallazgo con un desglose
por defecto según la severidad. No re-escanea ni modifica los hallazgos: solo
mejora el documento.
"""

# Desglose CVSS por defecto según severidad (para hallazgos sin ficha).
_DEFAULT_CVSS = {
    "critica": {"cvss": "9.1", "vector": "Red", "complejidad": "Baja", "privilegios": "Ninguno",
                "interaccion": "Ninguna", "alcance": "Sin cambios", "imp_c": "Alto", "imp_i": "Alto", "imp_d": "Ninguno"},
    "alta": {"cvss": "7.5", "vector": "Red", "complejidad": "Baja", "privilegios": "Ninguno",
             "interaccion": "Ninguna", "alcance": "Sin cambios", "imp_c": "Alto", "imp_i": "Ninguno", "imp_d": "Ninguno"},
    "media": {"cvss": "5.3", "vector": "Red", "complejidad": "Baja", "privilegios": "Ninguno",
              "interaccion": "Ninguna", "alcance": "Sin cambios", "imp_c": "Bajo", "imp_i": "Bajo", "imp_d": "Ninguno"},
    "baja": {"cvss": "3.1", "vector": "Red", "complejidad": "Alta", "privilegios": "Ninguno",
             "interaccion": "Requerida", "alcance": "Sin cambios", "imp_c": "Bajo", "imp_i": "Ninguno", "imp_d": "Ninguno"},
    "info": {"cvss": "0.0", "vector": "Red", "complejidad": "Baja", "privilegios": "Ninguno",
             "interaccion": "Ninguna", "alcance": "Sin cambios", "imp_c": "Ninguno", "imp_i": "Ninguno", "imp_d": "Ninguno"},
}


def _b(cvss, vector="Red", complejidad="Alta", privilegios="Ninguno", interaccion="Requerida",
       alcance="Sin cambios", imp_c="Bajo", imp_i="Ninguno", imp_d="Ninguno"):
    return {"cvss": cvss, "vector": vector, "complejidad": complejidad, "privilegios": privilegios,
            "interaccion": interaccion, "alcance": alcance, "imp_c": imp_c, "imp_i": imp_i, "imp_d": imp_d}


# tipo -> ficha. `cvss` incluye score + desglose; el resto son textos.
CATALOG = {
    "csp-missing": {
        "cwe": "CWE-693",
        "descripcion": (
            "El servidor no define la cabecera Content-Security-Policy (CSP). Sin una CSP, el "
            "navegador no restringe los orígenes desde los que se cargan scripts, estilos y otros "
            "recursos, lo que debilita la defensa en profundidad frente a Cross-Site Scripting (XSS) "
            "e inyección de contenido. Ante una eventual vulnerabilidad de XSS, la ausencia de CSP "
            "facilita su explotación."),
        "recomendacion": (
            "Definir una CSP restrictiva evitando comodines amplios y 'unsafe-inline', cubriendo al "
            "menos script-src, style-src, frame-ancestors y object-src 'none'. Conviene desplegarla "
            "primero en modo Report-Only para validar sin romper la aplicación."),
        "mas_info": "MDN Web Docs – Content-Security-Policy; OWASP – Content Security Policy Cheat Sheet",
        "cvss": _b("3.1"),
    },
    "csp-unsafe-inline": {
        "cwe": "CWE-79",
        "descripcion": (
            "La cabecera Content-Security-Policy definida por la aplicación incluye el valor "
            "'unsafe-inline' en las directivas script-src y/o style-src. Esto permite la ejecución "
            "de scripts y estilos embebidos en línea, debilitando la principal barrera que ofrece una "
            "CSP frente a ataques de Cross-Site Scripting (XSS)."),
        "recomendacion": (
            "Eliminar 'unsafe-inline' de script-src y style-src. Migrar los scripts y estilos "
            "embebidos a archivos externos y, cuando sea imprescindible mantener contenido en línea, "
            "autorizarlo mediante nonces o hashes por directiva."),
        "mas_info": "MDN Web Docs – Content-Security-Policy; OWASP – Content Security Policy Cheat Sheet",
        "cvss": _b("3.1"),
    },
    "hsts-missing": {
        "cwe": "CWE-319",
        "descripcion": (
            "El servidor no envía la cabecera Strict-Transport-Security (HSTS). Sin HSTS, un atacante "
            "en posición de intermediario podría forzar conexiones por HTTP en texto plano (downgrade) "
            "antes de que el navegador aplique HTTPS, exponiendo la sesión a intercepción."),
        "recomendacion": (
            "Agregar Strict-Transport-Security con un max-age prolongado (p. ej. 63072000), "
            "includeSubDomains y, si corresponde, preload, sirviéndola siempre sobre HTTPS."),
        "mas_info": "OWASP – HTTP Strict Transport Security Cheat Sheet",
        "cvss": _b("3.1", imp_c="Bajo"),
    },
    "xfo-missing": {
        "cwe": "CWE-1021",
        "descripcion": (
            "El servidor no define X-Frame-Options ni una directiva frame-ancestors equivalente en la "
            "CSP. Esto permite embeber la página en un iframe de un sitio de terceros, habilitando "
            "ataques de clickjacking donde se engaña al usuario para que interactúe con la aplicación "
            "sin saberlo."),
        "recomendacion": (
            "Agregar X-Frame-Options: DENY o SAMEORIGIN y, preferentemente, definir frame-ancestors en "
            "la CSP para un control más granular."),
        "mas_info": "OWASP – Clickjacking Defense Cheat Sheet",
        "cvss": _b("4.3", complejidad="Baja", imp_c="Ninguno", imp_i="Bajo"),
    },
    "xcto-missing": {
        "cwe": "CWE-693",
        "descripcion": (
            "El servidor no define X-Content-Type-Options: nosniff. Sin esta cabecera, algunos "
            "navegadores pueden inferir (MIME sniffing) el tipo de contenido de una respuesta, lo que "
            "puede derivar en la interpretación inesperada de contenido."),
        "recomendacion": "Agregar X-Content-Type-Options: nosniff en todas las respuestas.",
        "mas_info": "MDN Web Docs – X-Content-Type-Options",
        "cvss": _b("3.1"),
    },
    "referrer-missing": {
        "cwe": "CWE-200",
        "descripcion": (
            "El servidor no define Referrer-Policy. Sin esta política, el navegador puede incluir la "
            "URL completa de la página en la cabecera Referer al navegar hacia otros sitios, filtrando "
            "potencialmente rutas internas o parámetros sensibles."),
        "recomendacion": (
            "Definir Referrer-Policy (p. ej. strict-origin-when-cross-origin o no-referrer) según las "
            "necesidades de la aplicación."),
        "mas_info": "MDN Web Docs – Referrer-Policy",
        "cvss": _b("3.1"),
    },
    "permissions-missing": {
        "cwe": "CWE-693",
        "descripcion": (
            "El servidor no define Permissions-Policy. Esta cabecera permite restringir el acceso a "
            "APIs potentes del navegador (cámara, micrófono, geolocalización, etc.). Su ausencia no es "
            "una vulnerabilidad directa, pero reduce la defensa en profundidad."),
        "recomendacion": (
            "Definir Permissions-Policy deshabilitando las funcionalidades del navegador que la "
            "aplicación no utiliza."),
        "mas_info": "MDN Web Docs – Permissions-Policy",
        "cvss": _b("3.1", imp_c="Ninguno"),
    },
    "coop-missing": {
        "cwe": "CWE-693",
        "descripcion": (
            "El servidor no define Cross-Origin-Opener-Policy (COOP). Esta cabecera aísla el contexto "
            "de navegación respecto de ventanas de otros orígenes, mitigando ataques de canal lateral "
            "y de manipulación de ventanas cruzadas."),
        "recomendacion": (
            "Agregar Cross-Origin-Opener-Policy: same-origin cuando la aplicación no requiera "
            "interoperar con ventanas de otros orígenes."),
        "mas_info": "MDN Web Docs – Cross-Origin-Opener-Policy",
        "cvss": _b("3.1", imp_c="Ninguno"),
    },
    "server-version": {
        "cwe": "CWE-200",
        "descripcion": (
            "El servidor web revela su producto y versión exacta en la cabecera Server o en banners de "
            "servicio. Esta información facilita a un atacante identificar vulnerabilidades conocidas "
            "asociadas a esa versión específica y orientar sus ataques."),
        "recomendacion": (
            "Ocultar o normalizar la cabecera Server para no exponer producto ni versión. En Apache, "
            "ServerTokens Prod y ServerSignature Off; en nginx, server_tokens off; o normalizar mediante "
            "un proxy inverso."),
        "mas_info": "OWASP – Fingerprint Web Server; OWASP – HTTP Headers Cheat Sheet",
        "cvss": _b("3.1", complejidad="Baja", interaccion="Ninguna"),
    },
    "email-disclosure": {
        "cwe": "CWE-200",
        "descripcion": (
            "La aplicación expone direcciones de correo electrónico en el HTML servido. Estas "
            "direcciones pueden ser recolectadas por bots para campañas de spam y phishing dirigido "
            "contra los titulares de esas cuentas."),
        "recomendacion": (
            "Evitar exponer correos en texto plano en el HTML. Usar formularios de contacto, ofuscación "
            "u otros mecanismos que dificulten la recolección automatizada."),
        "mas_info": "OWASP – Information Leakage",
        "cvss": _b("3.1", complejidad="Baja", interaccion="Ninguna"),
    },
    "sensitive-file": {
        "cwe": "CWE-538",
        "descripcion": (
            "Se detectó un archivo o directorio sensible accesible públicamente (por ejemplo archivos "
            "de configuración, control de versiones, respaldos o credenciales). Estos recursos pueden "
            "exponer información crítica que facilita comprometer la aplicación o su infraestructura."),
        "recomendacion": (
            "Bloquear el acceso público al recurso, moverlo fuera del webroot y revisar si estuvo "
            "expuesto. Si contenía credenciales o secretos, rotarlos de inmediato."),
        "mas_info": "OWASP – Testing for Sensitive Information; CWE-538",
        "cvss": _b("7.5", complejidad="Baja", interaccion="Ninguna", imp_c="Alto"),
    },
    "tls-obsolete": {
        "cwe": "CWE-327",
        "descripcion": (
            "El servidor habilita versiones obsoletas del protocolo TLS (SSLv3, TLS 1.0 o TLS 1.1). "
            "Estas versiones presentan debilidades criptográficas conocidas (BEAST, POODLE, etc.) que, "
            "bajo ciertas condiciones, permiten a un atacante en posición de intermediario descifrar o "
            "manipular el tráfico."),
        "recomendacion": (
            "Deshabilitar SSLv3, TLS 1.0 y TLS 1.1; permitir únicamente TLS 1.2 y TLS 1.3 con suites "
            "de cifrado modernas (AEAD con ECDHE)."),
        "mas_info": "RFC 8996 – Deprecating TLS 1.0/1.1; OWASP – Transport Layer Protection Cheat Sheet",
        "cvss": _b("5.9", interaccion="Ninguna", imp_c="Alto"),
    },
    "tls-weak-cipher": {
        "cwe": "CWE-326",
        "descripcion": (
            "El servidor negocia suites de cifrado consideradas débiles según el análisis de nmap "
            "(nota inferior a A). Los cifrados débiles reducen la robustez del canal cifrado y pueden "
            "facilitar ataques criptográficos."),
        "recomendacion": (
            "Retirar los cifrados débiles; preferir suites AEAD (AES-GCM o ChaCha20-Poly1305) con "
            "intercambio de claves ECDHE (forward secrecy)."),
        "mas_info": "OWASP – TLS Cipher String Cheat Sheet",
        "cvss": _b("5.3", interaccion="Ninguna", imp_c="Bajo"),
    },
    "cookie-flags": {
        "cwe": "CWE-614",
        "descripcion": (
            "Se detectaron cookies emitidas sin todos los atributos de seguridad recomendados (Secure, "
            "HttpOnly, SameSite). Sin ellos, las cookies pueden viajar por canales no cifrados, ser "
            "accedidas por scripts del lado del cliente o enviarse en contextos de terceros, "
            "aumentando el riesgo de robo de sesión y CSRF."),
        "recomendacion": (
            "Marcar las cookies de sesión con Secure, HttpOnly y SameSite (Lax o Strict según el "
            "flujo). Revisar cada cookie y aplicar el atributo faltante."),
        "mas_info": "OWASP – Session Management Cheat Sheet",
        "cvss": _b("3.1", complejidad="Baja"),
    },
}


def tipo_de(dedup_key: str) -> str | None:
    """Mapea la clave de de-dup del hallazgo a un tipo del catálogo."""
    k = dedup_key or ""
    if k.startswith("header-missing:"):
        name = k.split(":", 1)[1]
        return {
            "content-security-policy": "csp-missing",
            "strict-transport-security": "hsts-missing",
            "x-frame-options": "xfo-missing",
            "x-content-type-options": "xcto-missing",
            "referrer-policy": "referrer-missing",
            "permissions-policy": "permissions-missing",
            "cross-origin-opener-policy": "coop-missing",
        }.get(name)
    if k == "csp:unsafe-inline":
        return "csp-unsafe-inline"
    if k.startswith("server-version:"):
        return "server-version"
    if k == "email-disclosure":
        return "email-disclosure"
    if k.startswith("ffuf:sensible:"):
        return "sensitive-file"
    if k == "tls:obsoletos":
        return "tls-obsolete"
    if k == "tls:least-strength":
        return "tls-weak-cipher"
    if k.startswith("cookie-flags:"):
        return "cookie-flags"
    return None


def enrich(vuln: dict) -> dict:
    """Devuelve el vuln enriquecido con descripción, desglose CVSS, recomendación,
    referencias y línea de CVE/CWE. `vuln` trae los campos del Finding."""
    ficha = CATALOG.get(tipo_de(vuln.get("dedup_key", "")))
    sev = vuln.get("severidad", "info")
    breakdown = dict(_DEFAULT_CVSS.get(sev, _DEFAULT_CVSS["info"]))

    if ficha:
        breakdown.update(ficha["cvss"])
        descripcion = ficha["descripcion"]
        recomendacion = ficha["recomendacion"]
        mas_info = ficha["mas_info"]
        cwe = ficha["cwe"]
    else:
        # sin ficha (p. ej. nuclei): usar los datos del propio hallazgo
        descripcion = vuln.get("evidencia") or vuln.get("titulo") or "—"
        recomendacion = vuln.get("recomendacion") or "—"
        mas_info = vuln.get("mas_info") or "—"
        cwe = vuln.get("cwe")

    # el CVSS numérico del hallazgo (nuclei) tiene prioridad si existe
    cvss = vuln.get("cvss") or breakdown["cvss"]

    cve = vuln.get("cve") or "No aplica"
    if cve and cve != "No aplica":
        cve_line = cve + (f" · {cwe}" if cwe else "")
    elif cwe:
        cve_line = f"No aplica. Debilidad de configuración asociada a {cwe}."
    else:
        cve_line = "No aplica."

    out = dict(vuln)
    out.update(
        descripcion=descripcion,
        recomendacion=recomendacion,
        mas_info=mas_info,
        cwe=cwe,
        cvss=cvss,
        cve_line=cve_line,
        vector=breakdown["vector"],
        complejidad=breakdown["complejidad"],
        privilegios=breakdown["privilegios"],
        interaccion=breakdown["interaccion"],
        alcance=breakdown["alcance"],
        imp_c=breakdown["imp_c"],
        imp_i=breakdown["imp_i"],
        imp_d=breakdown["imp_d"],
    )
    return out
