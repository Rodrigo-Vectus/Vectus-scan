import platform
import time

from worker.celery_app import celery_app


@celery_app.task(name="worker.tasks.ping")
def ping():
    """Tarea trivial de F0: confirma que el worker recibe y procesa tareas.

    El motor real del BIEC (ejecución por etapas de las herramientas de
    escaneo) se implementa en la Fase 2, respetando el principio rector:
    todo scan exige un objetivo con autorización asociada cargada en el
    sistema antes de poder lanzarse.
    """
    return {
        "pong": True,
        "worker_host": platform.node(),
        "timestamp": time.time(),
    }
