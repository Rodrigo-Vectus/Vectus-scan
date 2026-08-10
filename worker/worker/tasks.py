import platform
import time

from worker.celery_app import celery_app


@celery_app.task(name="worker.tasks.ping")
def ping():
    """Tarea trivial de smoke-test (F0)."""
    return {
        "pong": True,
        "worker_host": platform.node(),
        "timestamp": time.time(),
    }


@celery_app.task(name="worker.tasks.run_biec")
def run_biec_task(scan_id: int):
    """Ejecuta el BIEC para un scan. La lógica vive en worker.engine para
    poder testearla con un runner inyectado, sin Celery ni herramientas."""
    from worker.engine import run_biec

    run_biec(scan_id)
    return {"scan_id": scan_id, "done": True}
