FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ─────────────────────────────────────────────────────────────────────
# F0: imagen base del worker (solo runtime Python + Celery).
#
# Las herramientas de escaneo del BIEC (nmap, whatweb, dig/whois,
# subfinder/amass, gobuster/ffuf, nuclei, nikto, curl) se instalan en la
# FASE 2 (motor BIEC), junto con las capacidades de red acotadas
# (NET_RAW) que requieren nmap SYN / ssl-enum-ciphers. Aquí solo
# validamos la plomería Celery ↔ Redis.
# ─────────────────────────────────────────────────────────────────────

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker ./worker

CMD ["celery", "-A", "worker.celery_app", "worker", "--loglevel=info", "--concurrency=2"]
