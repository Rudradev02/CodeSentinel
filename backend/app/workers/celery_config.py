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

from kombu import Exchange, Queue

# Default queue
task_default_queue = "analysis"

# Multi-queue architecture (Phase 28)
task_queues = (
    Queue("analysis", Exchange("analysis"), routing_key="analysis"),
    Queue("workspace_dag", Exchange("workspace_dag"), routing_key="workspace_dag"),
    Queue("repo_heavy", Exchange("repo_heavy"), routing_key="repo_heavy"),
    Queue("repo_fast", Exchange("repo_fast"), routing_key="repo_fast"),
    Queue("compliance_attestation", Exchange("compliance_attestation"), routing_key="compliance_attestation"),
)

task_routes = {
    "backend.app.workers.tasks.run_analysis_task": {"queue": "analysis"},
    "backend.app.workers.tasks.run_workspace_scan_task": {"queue": "workspace_dag"},
}

# Broker resilience & fast failure
broker_connection_retry_on_startup = False
broker_connection_max_retries = 2
broker_connection_timeout = 2.0
redis_socket_timeout = 2.0
redis_socket_connect_timeout = 2.0
broker_transport_options = {
    "socket_timeout": 2.0,
    "socket_connect_timeout": 2.0,
}
