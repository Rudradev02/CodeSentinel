"""Celery configuration parameters for CodeSentinel worker."""

from backend.app.core.config import get_settings

settings = get_settings()

broker_url = settings.CELERY_BROKER_URL
result_backend = settings.CELERY_RESULT_BACKEND

task_serializer = "json"
result_serializer = "json"
accept_content = ["json"]
timezone = "UTC"
enable_utc = True

task_track_started = settings.CELERY_TASK_TRACK_STARTED
task_acks_late = True
worker_prefetch_multiplier = 1

# Default queue
task_default_queue = "analysis"
