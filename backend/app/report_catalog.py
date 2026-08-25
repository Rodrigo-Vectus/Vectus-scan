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

    # ── Vulnerabilidades de aplicación detectadas por wapiti (F8d) ──
    # `cvss: {}` deja el desglose por defecto según la severidad del hallazgo
    # (que la fija wapiti), manteniendo la tabla CVSS consistente con la severidad.
    # ── Librerías JS de cliente (dedup_key lib:*), confirmadas por OSV ──
    "js-library": {
        "cwe": "CWE-1395",
        "descripcion": (
            "La aplicación sirve al navegador del usuario una librería JavaScript de terceros en una "
            "versión con vulnerabilidades públicas conocidas. A diferencia del software del servidor, "
            "el código que se entrega al cliente es visible y su número de versión es verificable: no "
            "existe la posibilidad de que la distribución haya aplicado un parche manteniendo el "
            "número (backport), por lo que la versión observada confirma la exposición. La "
            "vulnerabilidad se ejecuta en el navegador de cada visitante, de modo que el impacto "
            "recae sobre los usuarios de la aplicación —típicamente ejecución de código en su sesión "
            "(XSS), manipulación del contenido mostrado o robo de datos del lado del cliente— y no "
            "sobre la infraestructura. Su explotación no requiere acceso previo ni credenciales."),
        "recomendacion": (
            "Actualizar la librería a una versión corregida y verificar que el archivo servido en "
            "producción sea efectivamente el nuevo (es habitual que quede una copia cacheada en el "
            "CDN o en el build). Si la actualización mayor implica cambios que rompen la aplicación, "
            "evaluar una versión de mantenimiento de la misma rama. Como práctica sostenida, "
            "incorporar al pipeline una verificación automática de dependencias del front-end para "
            "que este control no dependa de una auditoría puntual."),
        "mas_info": "OSV.dev – base de vulnerabilidades de código abierto; OWASP – Vulnerable and Outdated Components",
        "cvss": {},
    },
    # ── WordPress: plugins, temas y core (dedup_key wpscan:*) ──
    "wpscan-plugin": {
        "cwe": "CWE-1395",
        "descripcion": (
            "Se detectó en el sitio WordPress un plugin con vulnerabilidades registradas en la base "
            "pública de WPScan. Los plugins ejecutan código en el servidor con los mismos privilegios "
            "que el propio WordPress, por lo que una vulnerabilidad en uno de ellos puede comprometer "
            "el sitio completo, incluidos su base de datos y los archivos alojados. Los plugins son "
            "históricamente el vector de intrusión más frecuente en instalaciones de WordPress, muy "
            "por encima del núcleo. Es importante señalar el alcance de esta detección: WPScan "
            "identifica el plugin y lista las vulnerabilidades conocidas del componente, sin ejecutar "
            "prueba alguna contra el sitio; la aplicabilidad real depende de la versión instalada y "
            "de la configuración."),
        "recomendacion": (
            "Actualizar el plugin a la versión corregida indicada. Si el plugin ya no recibe "
            "mantenimiento del autor, reemplazarlo por una alternativa activa o retirarlo. Conviene "
            "además desinstalar —no solo desactivar— los plugins que no estén en uso: un plugin "
            "desactivado sigue presente en el disco y puede seguir siendo alcanzable."),
        "mas_info": "WPScan – WordPress Vulnerability Database; WordPress – Hardening WordPress",
        "cvss": {},
    },
    "wpscan-theme": {
        "cwe": "CWE-1395",
        "descripcion": (
            "Se detectó un tema de WordPress con vulnerabilidades registradas en la base pública de "
            "WPScan. Los temas incluyen código PHP que se ejecuta en el servidor, de modo que una "
            "vulnerabilidad en el tema activo tiene el mismo alcance potencial que una del núcleo. "
            "Los temas instalados pero no activos también permanecen accesibles en el sistema de "
            "archivos y pueden ser alcanzables. La detección identifica el componente y sus "
            "vulnerabilidades conocidas; no se ejecutó ninguna prueba de explotación contra el sitio."),
        "recomendacion": (
            "Actualizar el tema a la versión corregida. Eliminar los temas que no se usen, incluidos "
            "los que vienen por defecto con la instalación. Si el tema fue modificado a mano, migrar "
            "esas modificaciones a un tema hijo para que actualizar deje de implicar perder cambios."),
        "mas_info": "WPScan – WordPress Vulnerability Database; WordPress – Theme Handbook",
        "cvss": {},
    },
    "wpscan-core": {
        "cwe": "CWE-1395",
        "descripcion": (
            "La versión del núcleo de WordPress identificada en el sitio tiene vulnerabilidades "
            "públicas conocidas. El núcleo es la base sobre la que corren todos los plugins y temas, "
            "por lo que una vulnerabilidad a este nivel afecta al sitio entero. WordPress publica "
            "versiones de seguridad con detalle público de lo corregido, lo que reduce "
            "significativamente el esfuerzo necesario para atacar instalaciones desactualizadas una "
            "vez publicado el parche."),
        "recomendacion": (
            "Actualizar el núcleo a la última versión estable y dejar habilitadas las actualizaciones "
            "automáticas de seguridad de rama menor. Antes de actualizar, verificar la compatibilidad "
            "de los plugins críticos y contar con una copia de seguridad restaurable."),
        "mas_info": "WordPress – Security Releases; WPScan – WordPress Vulnerability Database",
        "cvss": {},
    },
    "wapiti-sqli": {
        "cwe": "CWE-89",
        "descripcion": (
            "Se detectó una inyección SQL: la aplicación incorpora entrada del usuario en una "
            "consulta a la base de datos sin sanearla adecuadamente. Un atacante puede alterar la "
            "consulta para leer o modificar datos, eludir la autenticación o, según el motor y los "
            "permisos, escalar el acceso sobre el sistema."),
        "recomendacion": (
            "Usar consultas parametrizadas (prepared statements) o un ORM que las aplique; nunca "
            "concatenar entrada del usuario en la consulta. Validar y restringir los tipos de dato "
            "esperados y aplicar el principio de mínimo privilegio en la cuenta de base de datos."),
        "mas_info": "OWASP – SQL Injection Prevention Cheat Sheet; CWE-89",
        "cvss": {},
    },
    "wapiti-xss": {
        "cwe": "CWE-79",
        "descripcion": (
            "Se detectó Cross-Site Scripting (XSS) reflejado: la aplicación devuelve entrada del "
            "usuario en la respuesta sin escaparla, permitiendo la ejecución de scripts en el "
            "navegador de la víctima. Puede derivar en robo de sesión, phishing o acciones en "
            "nombre del usuario."),
        "recomendacion": (
            "Escapar la salida según el contexto (HTML, atributo, JS, URL) y validar la entrada. "
            "Aplicar una Content-Security-Policy restrictiva como defensa en profundidad."),
        "mas_info": "OWASP – Cross Site Scripting Prevention Cheat Sheet; CWE-79",
        "cvss": {},
    },
    "wapiti-xss-stored": {
        "cwe": "CWE-79",
        "descripcion": (
            "Se detectó Cross-Site Scripting (XSS) almacenado: la entrada maliciosa se persiste en "
            "el servidor y se sirve a otros usuarios, ejecutándose en sus navegadores. Su impacto "
            "suele ser mayor que el del XSS reflejado porque no requiere interacción dirigida."),
        "recomendacion": (
            "Escapar la salida según contexto, validar y sanear la entrada antes de almacenarla, y "
            "aplicar una Content-Security-Policy restrictiva."),
        "mas_info": "OWASP – Cross Site Scripting Prevention Cheat Sheet; CWE-79",
        "cvss": {},
    },
    "wapiti-exec": {
        "cwe": "CWE-78",
        "descripcion": (
            "Se detectó ejecución de comandos: la aplicación pasa entrada del usuario a un "
            "intérprete de comandos del sistema operativo o de código, permitiendo ejecutar "
            "comandos arbitrarios en el servidor. Es una de las vulnerabilidades de mayor impacto."),
        "recomendacion": (
            "Evitar invocar el shell con entrada del usuario; usar APIs seguras con argumentos "
            "separados y listas blancas. Ejecutar con mínimos privilegios y aislar el proceso."),
        "mas_info": "OWASP – Command Injection; CWE-78",
        "cvss": {},
    },
    "wapiti-path-traversal": {
        "cwe": "CWE-22",
        "descripcion": (
            "Se detectó Path Traversal: la aplicación construye rutas de archivo con entrada del "
            "usuario sin restringirla, permitiendo acceder a archivos fuera del directorio previsto "
            "(p. ej. /etc/passwd) o incluir archivos no autorizados."),
        "recomendacion": (
            "Validar y normalizar las rutas contra una lista blanca; no usar entrada del usuario "
            "directamente en operaciones de archivo. Confinar el acceso a un directorio base."),
        "mas_info": "OWASP – Path Traversal; CWE-22",
        "cvss": {},
    },
    "wapiti-ldap": {
        "cwe": "CWE-90",
        "descripcion": (
            "Se detectó inyección LDAP: la entrada del usuario se incorpora a una consulta LDAP sin "
            "sanearla, permitiendo alterar la consulta para eludir controles de autenticación o "
            "extraer información del directorio."),
        "recomendacion": (
            "Escapar los metacaracteres LDAP de la entrada del usuario y usar APIs de consulta "
            "parametrizadas. Aplicar mínimo privilegio en la cuenta de enlace (bind)."),
        "mas_info": "OWASP – LDAP Injection Prevention Cheat Sheet; CWE-90",
        "cvss": {},
    },
    "wapiti-crlf": {
        "cwe": "CWE-93",
        "descripcion": (
            "Se detectó inyección CRLF: la aplicación refleja entrada del usuario en cabeceras HTTP "
            "sin filtrar los caracteres de retorno de carro y salto de línea, permitiendo inyectar "
            "cabeceras o dividir la respuesta (HTTP response splitting)."),
        "recomendacion": (
            "Eliminar o codificar los caracteres CR/LF de cualquier entrada que se incorpore a "
            "cabeceras de respuesta. Usar APIs que impidan la inyección de cabeceras."),
        "mas_info": "OWASP – CRLF Injection; CWE-93",
        "cvss": {},
    },
    "wapiti-ssrf": {
        "cwe": "CWE-918",
        "descripcion": (
            "Se detectó SSRF (Server-Side Request Forgery): la aplicación realiza peticiones a URLs "
            "controladas por el usuario, permitiendo alcanzar servicios internos, metadatos de la "
            "nube u otros recursos no expuestos."),
        "recomendacion": (
            "Validar y restringir los destinos con una lista blanca de dominios/IPs; bloquear "
            "rangos internos y de metadatos. No seguir redirecciones hacia destinos no permitidos."),
        "mas_info": "OWASP – Server Side Request Forgery Prevention Cheat Sheet; CWE-918",
        "cvss": {},
    },
    "wapiti-xxe": {
        "cwe": "CWE-611",
        "descripcion": (
            "Se detectó inyección de entidad externa XML (XXE): el analizador XML procesa entidades "
            "externas definidas por el usuario, permitiendo leer archivos locales, realizar SSRF o "
            "provocar denegación de servicio."),
        "recomendacion": (
            "Deshabilitar el procesamiento de entidades externas y DTD en el parser XML. Preferir "
            "formatos y bibliotecas que no expandan entidades por defecto."),
        "mas_info": "OWASP – XML External Entity Prevention Cheat Sheet; CWE-611",
        "cvss": {},
    },
    "wapiti-open-redirect": {
        "cwe": "CWE-601",
        "descripcion": (
            "Se detectó una redirección abierta: la aplicación redirige a una URL controlada por el "
            "usuario sin validarla, lo que facilita ataques de phishing al aparentar provenir de un "
            "dominio confiable."),
        "recomendacion": (
            "Validar el destino de la redirección contra una lista blanca de rutas o dominios "
            "propios; evitar redirigir a URLs absolutas provistas por el usuario."),
        "mas_info": "OWASP – Unvalidated Redirects and Forwards Cheat Sheet; CWE-601",
        "cvss": {},
    },
    "wapiti-html-injection": {
        "cwe": "CWE-79",
        "descripcion": (
            "Se detectó inyección de HTML: la aplicación refleja entrada del usuario en la página "
            "sin sanearla, permitiendo insertar marcado que altera el contenido o habilita ataques "
            "de ingeniería social."),
        "recomendacion": (
            "Escapar la salida en contexto HTML y validar la entrada. Aplicar una CSP restrictiva."),
        "mas_info": "OWASP – Cross Site Scripting Prevention Cheat Sheet; CWE-79",
        "cvss": {},
    },
    "wapiti-file-upload": {
        "cwe": "CWE-434",
        "descripcion": (
            "Se detectó carga de archivos sin restricciones: la aplicación permite subir archivos "
            "sin validar tipo, contenido o destino, habilitando potencialmente la carga y ejecución "
            "de código en el servidor (web shell)."),
        "recomendacion": (
            "Validar el tipo real y la extensión contra una lista blanca, almacenar fuera de la raíz "
            "web sin permisos de ejecución y renombrar los archivos. Limitar tamaño y escanear."),
        "mas_info": "OWASP – Unrestricted File Upload; CWE-434",
        "cvss": {},
    },
    "wapiti-htaccess": {
        "cwe": "CWE-538",
        "descripcion": (
            "Se detectó una elusión de restricciones .htaccess: recursos que deberían estar "
            "protegidos resultan accesibles, exponiendo contenido o funcionalidad restringida."),
        "recomendacion": (
            "Revisar y reforzar las reglas de control de acceso del servidor; no depender solo de "
            ".htaccess para proteger recursos sensibles y verificar la configuración efectiva."),
        "mas_info": "OWASP – Testing for Bypassing Authorization Schema; CWE-538",
        "cvss": {},
    },
    "wapiti-backup": {
        "cwe": "CWE-530",
        "descripcion": (
            "Se detectó un archivo de respaldo accesible (p. ej. .bak, .old, .zip). Estos archivos "
            "suelen contener código fuente, credenciales o datos que no deberían ser públicos."),
        "recomendacion": (
            "Eliminar los archivos de respaldo del servidor web y evitar generarlos en rutas "
            "accesibles. Bloquear extensiones de respaldo a nivel de servidor."),
        "mas_info": "OWASP – Review Old Backup and Unreferenced Files; CWE-530",
        "cvss": {},
    },
    "wapiti-dangerous-file": {
        "cwe": "CWE-538",
        "descripcion": (
            "Se detectó un archivo potencialmente peligroso o sensible accesible en el servidor, "
            "que puede exponer información o funcionalidad no destinada al público."),
        "recomendacion": (
            "Retirar el archivo del árbol web o restringir su acceso; revisar qué recursos se "
            "publican y aplicar controles de acceso adecuados."),
        "mas_info": "OWASP – Review Webserver Metafiles for Information Leakage; CWE-538",
        "cvss": {},
    },
    "wapiti-log4shell": {
        "cwe": "CWE-502",
        "descripcion": (
            "Se detectó exposición a Log4Shell (CVE-2021-44228): una versión vulnerable de Log4j "
            "permite ejecución remota de código a través de la resolución de expresiones JNDI en "
            "datos registrados."),
        "recomendacion": (
            "Actualizar Log4j a una versión corregida (2.17.1 o superior) de inmediato; mitigar "
            "deshabilitando la búsqueda JNDI si no es posible actualizar."),
        "mas_info": "Apache – Log4j Security; CVE-2021-44228",
        "cvss": {},
    },
    "wapiti-spring4shell": {
        "cwe": "CWE-94",
        "descripcion": (
            "Se detectó exposición a Spring4Shell: una vulnerabilidad en Spring que puede permitir "
            "ejecución remota de código bajo ciertas configuraciones."),
        "recomendacion": (
            "Actualizar Spring Framework a una versión corregida y revisar la configuración de "
            "binding de parámetros expuesta."),
        "mas_info": "Spring – Security Advisories; CVE-2022-22965",
        "cvss": {},
    },
    "wapiti-http-methods": {
        "cwe": "CWE-16",
        "descripcion": (
            "El servidor habilita métodos HTTP potencialmente peligrosos (p. ej. TRACE, PUT, "
            "DELETE). Métodos como TRACE pueden facilitar ataques de Cross-Site Tracing, y PUT/"
            "DELETE, la modificación no autorizada de recursos si no están debidamente controlados."),
        "recomendacion": (
            "Deshabilitar los métodos HTTP que la aplicación no utiliza, dejando solo los "
            "necesarios (habitualmente GET, POST y HEAD)."),
        "mas_info": "OWASP – Test HTTP Methods; CWE-16",
        "cvss": {},
    },
    "wapiti-stack-trace": {
        "cwe": "CWE-209",
        "descripcion": (
            "Se detectó divulgación de stack trace: ante un error, la aplicación devuelve trazas "
            "internas que revelan rutas, tecnologías, consultas o detalles de implementación útiles "
            "para un atacante."),
        "recomendacion": (
            "Configurar el manejo de errores para no exponer trazas al cliente; registrar el "
            "detalle solo del lado servidor y mostrar mensajes genéricos."),
        "mas_info": "OWASP – Improper Error Handling; CWE-209",
        "cvss": {},
    },
    "wapiti-full-path": {
        "cwe": "CWE-200",
        "descripcion": (
            "Se detectó divulgación de la ruta absoluta de la aplicación en el servidor, "
            "información que facilita otros ataques (p. ej. LFI o traversal)."),
        "recomendacion": (
            "Evitar exponer rutas del sistema en mensajes de error o respuestas; configurar el "
            "manejo de errores para no revelar detalles internos."),
        "mas_info": "OWASP – Information Leakage; CWE-200",
        "cvss": {},
    },
}


def tipo_de(dedup_key: str, titulo: str | None = None) -> str | None:
    """Mapea la clave de de-dup del hallazgo a un tipo del catálogo.

    `titulo` es opcional y solo se usa donde la clave no alcanza para
    distinguir el tipo (hallazgos de WPScan)."""
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
    if k.startswith("lib:"):
        return "js-library"
    if k.startswith("wpscan:"):
        # El dedup_key es wpscan:<nombre-del-componente>:<cve>, así que el
        # tipo (plugin / tema / núcleo) hay que leerlo del título, que el
        # parser emite como "Plugin vulnerable: …" / "Tema vulnerable: …" /
        # "Núcleo de WordPress vulnerable: …".
        t = (titulo or "").lower()
        if t.startswith("tema"):
            return "wpscan-theme"
        if t.startswith("núcleo") or t.startswith("nucleo"):
            return "wpscan-core"
        return "wpscan-plugin"
    if k.startswith("wapiti:"):
        # wapiti:<slug>:<path>:<param> → ficha "wapiti-<slug>" si existe.
        slug = k.split(":", 2)[1] if k.count(":") >= 1 else ""
        tipo = f"wapiti-{slug}"
        return tipo if tipo in CATALOG else None
    return None



# ─── composición de la descripción del informe ───────────────────────
# La ficha explica QUÉ es el hallazgo y por qué importa (texto curado); los
# datos del propio hallazgo dicen QUÉ se observó en ESTE objetivo. Antes se
# usaba una cosa o la otra; ahora se combinan en un desglose para que la
# descripción del .docx tenga contexto además del dato técnico.

_HERRAMIENTA_ES = {
    "nmap": "nmap (escaneo de puertos y servicios)",
    "whatweb": "whatweb (identificación de tecnologías)",
    "nuclei": "nuclei (plantillas de detección de vulnerabilidades)",
    "nikto": "nikto (revisión de servidor web)",
    "ffuf": "ffuf (descubrimiento de contenido)",
    "curl": "curl (análisis de cabeceras HTTP)",
    "wapiti": "wapiti (pruebas activas de detección sobre la aplicación)",
    "wpscan": "WPScan (enumeración de WordPress)",
    "retire.js": "retire.js (firmas de librerías JavaScript)",
    "subfinder": "subfinder (enumeración pasiva de subdominios)",
    "osv": "OSV.dev (base pública de vulnerabilidades)",
}


def _herramientas_es(origen: str) -> str:
    """'retire.js, whatweb' → texto legible para el informe."""
    partes = [h.strip() for h in (origen or "").split(",") if h.strip()]
    if not partes:
        return ""
    return "; ".join(_HERRAMIENTA_ES.get(h.lower(), h) for h in partes)


def descripcion_bloques(vuln: dict, ficha: dict | None) -> list[str]:
    """Desglose de la descripción, como lista de párrafos.

    Orden: qué es y por qué importa → qué se observó en este objetivo →
    dónde → cómo se detectó. Se omite todo bloque sin contenido real: no se
    inventa nada para rellenar (regla de oro)."""
    bloques: list[str] = []

    base = ficha["descripcion"] if ficha else ""
    if base:
        bloques.append(base)

    evidencia = (vuln.get("evidencia") or "").strip()
    if evidencia:
        # Sin ficha, la evidencia ES la descripción: no se la rotula como
        # hallazgo observado para no dejar el bloque huérfano.
        bloques.append(f"Hallazgo observado: {evidencia}" if base else evidencia)
    elif not base:
        bloques.append(vuln.get("titulo") or "—")

    # No se repiten acá el sistema afectado, los CVE ni las ocurrencias: la
    # plantilla ya tiene campos propios para los dos primeros y la tabla CVSS
    # muestra el tercero. Duplicarlos alargaba la ficha sin agregar nada.

    herramientas = _herramientas_es(vuln.get("herramienta_origen", ""))
    if herramientas:
        bloques.append(
            f"Detectado con: {herramientas}. "
            "El barrido no ejecuta explotación: la detección no implica que la "
            "vulnerabilidad haya sido aprovechada contra el objetivo."
        )

    return bloques


def enrich(vuln: dict) -> dict:
    """Devuelve el vuln enriquecido con descripción, desglose CVSS, recomendación,
    referencias y línea de CVE/CWE. `vuln` trae los campos del Finding."""
    ficha = CATALOG.get(tipo_de(vuln.get("dedup_key", ""), vuln.get("titulo")))
    sev = vuln.get("severidad", "info")
    breakdown = dict(_DEFAULT_CVSS.get(sev, _DEFAULT_CVSS["info"]))

    if ficha:
        breakdown.update(ficha["cvss"])
        # La recomendación del propio hallazgo es específica (trae versión de
        # corrección, parámetro afectado, etc.); la de la ficha es genérica.
        # Se prefiere la específica cuando existe y se completa con la ficha.
        propia = (vuln.get("recomendacion") or "").strip()
        generica = ficha["recomendacion"]
        if propia and propia not in ("—", "(genérica del parser)"):
            recomendacion = f"{propia} {generica}" if generica else propia
        else:
            recomendacion = generica
        mas_info = vuln.get("mas_info") or ficha["mas_info"]
        cwe = vuln.get("cwe") or ficha["cwe"]
    else:
        recomendacion = vuln.get("recomendacion") or "—"
        mas_info = vuln.get("mas_info") or "—"
        cwe = vuln.get("cwe")

    bloques = descripcion_bloques(vuln, ficha)
    descripcion = "\n".join(bloques)

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
        descripcion_bloques=bloques,
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
