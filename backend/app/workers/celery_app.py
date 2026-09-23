"""Celery application instance initialization."""

from celery import Celery
from backend.app.workers import celery_config

celery_app = Celery("codesentinel")
celery_app.config_from_object(celery_config)

# Explicitly import tasks so Celery registers them immediately
import backend.app.workers.tasks  # noqa: F401
