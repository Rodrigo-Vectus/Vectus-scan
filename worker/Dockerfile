FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Versiones de los binarios Go (releases oficiales). Se pueden sobreescribir
# con --build-arg si sale una versión nueva.
ARG NUCLEI_VERSION=3.3.1
ARG SUBFINDER_VERSION=2.6.6
ARG FFUF_VERSION=2.1.0
# nikto ya no está en Debian; se instala desde su repo oficial (script Perl).
ARG NIKTO_VERSION=2.5.0

WORKDIR /app

# ── Herramientas del BIEC vía apt ──
# nikto NO se instala por apt (fue removido de Debian): se agrega abajo desde
# su repo. Se incluye perl + Net::SSLeay para que nikto escanee HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap whatweb dnsutils whois curl dirb \
        perl libnet-ssleay-perl \
        ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# ── nikto desde el repo oficial (Perl, no compila) ──
RUN set -eux; cd /tmp; \
    curl -sSL -o nikto.tar.gz "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz"; \
    tar -xzf nikto.tar.gz -C /opt; \
    mv "/opt/nikto-${NIKTO_VERSION}" /opt/nikto; \
    cp /opt/nikto/program/nikto.conf.default /etc/nikto.conf; \
    printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto; \
    chmod +x /usr/local/bin/nikto; \
    rm -f /tmp/nikto.tar.gz; \
    nikto -Version

# ── Binarios Go (nuclei, subfinder, ffuf) desde releases oficiales ──
RUN set -eux; cd /tmp; \
    curl -sSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    unzip -o nuclei.zip nuclei -d /usr/local/bin; \
    curl -sSL -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip"; \
    unzip -o subfinder.zip subfinder -d /usr/local/bin; \
    curl -sSL -o ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz"; \
    tar -xzf ffuf.tar.gz -C /usr/local/bin ffuf; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/ffuf; \
    rm -f /tmp/*.zip /tmp/*.tar.gz

# ── Templates de nuclei (no bloquea el build si no hay red en build-time) ──
RUN nuclei -update-templates >/dev/null 2>&1 || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker ./worker

CMD ["celery", "-A", "worker.celery_app", "worker", "--loglevel=info", "--concurrency=2"]
