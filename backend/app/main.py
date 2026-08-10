import redis
from celery.result import AsyncResult
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.celery_client import celery_client
from app.config import settings
from app.db import check_database

app = FastAPI(title=settings.app_name, version="0.1.0")

# CORS abierto en F0 para facilitar el desarrollo local.
# Se restringe a orígenes concretos en fases posteriores.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def check_redis() -> bool:
    try:
        client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            socket_connect_timeout=2,
        )
        return bool(client.ping())
    except Exception:
        return False


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    """Smoke-test integral: reporta estado de Postgres y Redis."""
    db_ok = check_database()
    redis_ok = check_redis()
    status = "ok" if (db_ok and redis_ok) else "degraded"
    return {
        "status": status,
        "service": settings.app_name,
        "environment": settings.environment,
        "checks": {"database": db_ok, "redis": redis_ok},
    }


# ─── Endpoints de depuración (solo F0) ──────────────────────────────
# Prueban el circuito backend → Redis → worker → resultado.
# Se eliminan cuando el motor real de scans llegue en la Fase 2.

@app.post("/debug/ping-worker")
def ping_worker():
    result = celery_client.send_task("worker.tasks.ping")
    return {"task_id": result.id}


@app.get("/debug/task/{task_id}")
def task_status(task_id: str):
    res = AsyncResult(task_id, app=celery_client)
    return {
        "task_id": task_id,
        "status": res.status,
        "result": res.result if res.ready() else None,
    }
