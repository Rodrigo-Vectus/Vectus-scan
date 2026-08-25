import os
import platform
import shutil
import time
from pathlib import Path

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


@celery_app.task(name="worker.tasks.consolidate_findings")
def consolidate_findings_task(scan_id: int):
    """Reprocesa el raw guardado y reconstruye los hallazgos (F3)."""
    from worker.consolidate import run

    total = run(scan_id)
    return {"scan_id": scan_id, "findings": total}


@celery_app.task(name="worker.tasks.delete_scan_data")
def delete_scan_data_task(scan_id: int):
    """Borra la evidencia cruda de un scan eliminado desde el backend.

    El volumen `scandata` solo está montado en el worker, por eso el
    borrado del disco se delega acá.

    Guarda de seguridad: el directorio se arma con el id como entero y se
    verifica que el path resuelto sea hijo directo de la raíz de scandata
    antes de borrar nada. Un id manipulado no puede apuntar afuera.
    """
    root = Path(os.environ.get("SCAN_DATA_ROOT", "/data/scans")).resolve()

    try:
        sid = int(scan_id)
    except (TypeError, ValueError):
        return {"scan_id": scan_id, "deleted": False, "reason": "id invalido"}
    if sid <= 0:
        return {"scan_id": scan_id, "deleted": False, "reason": "id invalido"}

    target = (root / str(sid)).resolve()
    if target.parent != root or not target.is_dir():
        return {"scan_id": sid, "deleted": False, "reason": "no existe"}

    shutil.rmtree(target)
    return {"scan_id": sid, "deleted": True}
