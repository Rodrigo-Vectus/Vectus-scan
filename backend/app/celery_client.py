from celery import Celery

from app.config import settings

# El backend NO define tareas: solo las despacha por nombre (send_task).
# Las tareas viven en la imagen del worker. Esto mantiene ambos servicios
# desacoplados y evita que el backend cargue las dependencias de escaneo.
celery_client = Celery(
    "vectus_backend",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
