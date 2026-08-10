#!/bin/sh
set -e

echo "[entrypoint] aplicando migraciones (alembic upgrade head)..."
alembic upgrade head

echo "[entrypoint] migraciones OK. Iniciando: $@"
exec "$@"
