import os

from celery import Celery

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
BROKER_DB = os.getenv("CELERY_BROKER_DB", "0")
RESULT_DB = os.getenv("CELERY_RESULT_DB", "1")

celery_app = Celery(
    "vectus_worker",
    broker=f"redis://{REDIS_HOST}:{REDIS_PORT}/{BROKER_DB}",
    backend=f"redis://{REDIS_HOST}:{REDIS_PORT}/{RESULT_DB}",
    include=["worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)
