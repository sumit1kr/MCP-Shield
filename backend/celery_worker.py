from celery import Celery
from app.config import settings

# Initialize Celery app instance with broker and backend pointing to Redis
celery_app = Celery(
    "mcpshield",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks.celery_tasks"]
)

# Optional configuration settings
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_default_queue="mcpshield_scans"
)
