"""Celery background worker task for repository static analysis."""

from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
from typing import Optional

from sqlalchemy.exc import OperationalError

from analyzer.config.settings import AnalysisConfig
from analyzer.engine.pipeline import AnalysisPipeline
from analyzer.models.errors import AnalysisCancelledError
from analyzer.workspace.compliance_rollup import FleetComplianceEvaluator
from analyzer.workspace.dag import WorkspaceDAG
from analyzer.workspace.federated_contracts import FederatedContractRegistry
from analyzer.workspace.models import RepositoryMember, WorkspaceManifest
from backend.app.db.sync_session import get_sync_db
from backend.app.models.job import AnalysisJob
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.models.workspace import Workspace, WorkspaceRepository, WorkspaceSnapshot
from backend.app.services.cache import AnalysisCacheService
from backend.app.services.persistence import PersistenceService
from backend.app.services.progress import ProgressPublisher
from backend.app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="backend.app.workers.tasks.run_analysis_task",
    autoretry_for=(OperationalError,),
    max_retries=3,
    retry_backoff=True,
)
def run_analysis_task(self, job_id: str) -> dict:
    """Execute repository analysis in background worker.
    
    Receives job_id primarily; loads repository details and configuration from database
    using a synchronous database session. Emits real-time progress via Redis Pub/Sub,
    supports cooperative cancellation, and atomically persists the resulting snapshot.
    """
    logger.info("Worker picked up analysis job: %s (task_id: %s)", job_id, self.request.id)

    # 1. Fetch Job and Repository from Database
    with get_sync_db() as db:
        job = db.query(AnalysisJob).filter_by(id=job_id).first()
        if not job:
            logger.error("AnalysisJob %s not found in database", job_id)
            return {"job_id": job_id, "status": "NOT_FOUND"}

        # Store Celery task ID on the job record if not already set
        if not job.celery_task_id:
            job.celery_task_id = self.request.id
            db.commit()

        # Check if already cancelled
        if ProgressPublisher.is_cancelled(job_id) or job.status == "CANCELLED":
            logger.info("Job %s was cancelled before worker started", job_id)
            job.status = "CANCELLED"
            job.completed_at = datetime.now(timezone.utc)
            job.progress_message = "Analysis cancelled before execution"
            db.commit()
            ProgressPublisher.publish_progress(
                job_id, "CANCELLED", job.progress_percent, "CANCELLED", "Analysis cancelled before execution"
            )
            return {"job_id": job_id, "status": "CANCELLED"}

        repository = db.query(Repository).filter_by(id=job.repository_id).first()
        if not repository:
            logger.error("Repository %s not found for job %s", job.repository_id, job_id)
            job.status = "FAILED"
            job.completed_at = datetime.now(timezone.utc)
            job.error_message = f"Repository {job.repository_id} not found"
            db.commit()
            ProgressPublisher.publish_progress(
                job_id, "FAILED", 0, "FAILED", error_message=f"Repository {job.repository_id} not found"
            )
            return {"job_id": job_id, "status": "FAILED"}

        repo_id = repository.id
        repo_path = repository.path
        repo_name = repository.name
        config_dict = job.configuration

        # Mark job as RUNNING
        job.status = "RUNNING"
        job.started_at = datetime.now(timezone.utc)
        job.progress_percent = 5
        job.progress_stage = "INITIALIZING"
        job.progress_message = "Initializing analysis pipeline..."
        db.commit()

    ProgressPublisher.publish_progress(
        job_id, "RUNNING", 5, "INITIALIZING", "Initializing analysis pipeline..."
    )

    # 2. Setup Progress and Cancellation Callbacks
    def on_progress(stage: str, percent: int, message: str) -> None:
        ProgressPublisher.publish_progress(job_id, "RUNNING", percent, stage, message)
        try:
            with get_sync_db() as db_inner:
                j = db_inner.query(AnalysisJob).filter_by(id=job_id).first()
                if j and j.status == "RUNNING":
                    j.progress_percent = percent
                    j.progress_stage = stage
                    j.progress_message = message
                    db_inner.commit()
        except Exception as exc:
            logger.debug("Minor failure updating DB progress for %s: %s", job_id, exc)

    def is_cancelled() -> bool:
        return ProgressPublisher.is_cancelled(job_id)

    # 3. Instantiate Pipeline & Run Analysis
    try:
        analysis_config: Optional[AnalysisConfig] = None
        if config_dict and isinstance(config_dict, dict):
            try:
                clean_dict = {k: v for k, v in config_dict.items() if v is not None}
                analysis_config = AnalysisConfig(**clean_dict)
            except Exception as parse_err:
                logger.warning("Could not parse AnalysisConfig from job dict: %s", parse_err)

        mode = config_dict.get("mode", "full") if config_dict and isinstance(config_dict, dict) else "full"
        pipeline = AnalysisPipeline(analysis_config=analysis_config)
        result = pipeline.run(
            target_path=repo_path,
            repository_name=repo_name,
            analysis_config=analysis_config,
            on_progress=on_progress,
            is_cancelled=is_cancelled,
            mode=mode,
        )

        # 4. Atomic Persistence & Cache Storage
        with get_sync_db() as db_sync:
            snapshot = PersistenceService.save_analysis_snapshot_sync(
                db=db_sync,
                repository_id=repo_id,
                result=result,
                config_dict=config_dict,
            )

            # Store in cache
            if result.repository and result.repository.commit_hash:
                AnalysisCacheService.set_cached_snapshot_id(
                    repo_id, result.repository.commit_hash, snapshot.id
                )

            # Mark job COMPLETED
            job_record = db_sync.query(AnalysisJob).filter_by(id=job_id).first()
            if job_record:
                job_record.status = "COMPLETED"
                job_record.snapshot_id = snapshot.id
                job_record.completed_at = datetime.now(timezone.utc)
                job_record.progress_percent = 100
                job_record.progress_stage = "COMPLETED"
                job_record.progress_message = "Analysis completed successfully"
                db_sync.commit()

        ProgressPublisher.publish_progress(
            job_id,
            "COMPLETED",
            100,
            "COMPLETED",
            "Analysis completed successfully",
            snapshot_id=snapshot.id,
            repository_id=repo_id,
        )
        ProgressPublisher.clear_cancellation(job_id)
        logger.info("Analysis job %s completed successfully (snapshot: %s)", job_id, snapshot.id)
        return {"job_id": job_id, "status": "COMPLETED", "snapshot_id": snapshot.id}

    except AnalysisCancelledError:
        logger.info("Analysis job %s was cooperatively cancelled", job_id)
        with get_sync_db() as db_cancel:
            j = db_cancel.query(AnalysisJob).filter_by(id=job_id).first()
            if j:
                j.status = "CANCELLED"
                j.completed_at = datetime.now(timezone.utc)
                j.progress_stage = "CANCELLED"
                j.progress_message = "Analysis was cancelled by user"
                db_cancel.commit()

        ProgressPublisher.publish_progress(
            job_id, "CANCELLED", 0, "CANCELLED", "Analysis was cancelled by user"
        )
        ProgressPublisher.clear_cancellation(job_id)
        return {"job_id": job_id, "status": "CANCELLED"}

    except Exception as exc:
        logger.exception("Analysis job %s failed with error: %s", job_id, exc)
        with get_sync_db() as db_err:
            j = db_err.query(AnalysisJob).filter_by(id=job_id).first()
            if j:
                j.status = "FAILED"
                j.completed_at = datetime.now(timezone.utc)
                j.progress_stage = "FAILED"
                j.error_message = str(exc)
                db_err.commit()

        ProgressPublisher.publish_progress(
            job_id, "FAILED", 0, "FAILED", error_message=str(exc)
        )
        ProgressPublisher.clear_cancellation(job_id)
        return {"job_id": job_id, "status": "FAILED", "error": str(exc)}


@celery_app.task(
    bind=True,
    name="backend.app.workers.tasks.run_workspace_scan_task",
    autoretry_for=(OperationalError,),
    max_retries=3,
    retry_backoff=True,
)
def run_workspace_scan_task(self, workspace_id: str, manifest_path: Optional[str] = None) -> dict:
    """Execute multi-repository topological workspace scan (Phase 28)."""
    task_id = getattr(self.request, "id", None) or "local_task"
    logger.info("Worker picked up workspace scan task: %s (task_id: %s)", workspace_id, task_id)

    # 1. Fetch Workspace from Database
    with get_sync_db() as db:
        workspace = db.query(Workspace).filter_by(id=workspace_id).first()
        if not workspace:
            logger.error("Workspace %s not found in database", workspace_id)
            return {"workspace_id": workspace_id, "status": "NOT_FOUND"}

        # Resolve manifest
        target_manifest_path = manifest_path or workspace.manifest_path
        manifest: Optional[WorkspaceManifest] = None
        if target_manifest_path and Path(target_manifest_path).exists():
            manifest = WorkspaceManifest.from_yaml_file(target_manifest_path)
        elif workspace.repository_links:
            # Construct from DB associations
            members = []
            for link in workspace.repository_links:
                repo_record = db.query(Repository).filter_by(id=link.repository_id).first()
                r_path = repo_record.path if repo_record else f"./repos/{link.repository_id}"
                members.append(
                    RepositoryMember(
                        id=link.repository_id,
                        path=r_path,
                        role=link.role,
                        criticality=link.criticality,
                        depends_on=link.depends_on or [],
                    )
                )
            manifest = WorkspaceManifest(
                version="1.0",
                workspace_id=workspace.slug or workspace.id,
                name=workspace.name,
                organization_id=workspace.organization_id,
                repositories=members,
            )
        else:
            logger.error("No valid manifest or repository links found for workspace %s", workspace_id)
            return {"workspace_id": workspace_id, "status": "FAILED", "error": "Missing manifest and repository links"}

    # 2. Build DAG and execution waves
    dag = WorkspaceDAG(manifest)
    waves = dag.get_execution_waves()
    federated_registry = FederatedContractRegistry(workspace_id=manifest.workspace_id)

    ProgressPublisher.publish_progress(
        f"workspace_{workspace_id}", "RUNNING", 10, "DAG_SCHEDULED", f"Scheduled {len(waves)} execution waves"
    )

    # 3. Execute wave-by-wave analysis
    repo_results: dict[str, Any] = {}
    analysis_snapshot_ids: list[str] = []

    total_repos = len(manifest.repositories)
    repos_done = 0

    try:
        for wave_idx, wave in enumerate(waves):
            logger.info("Executing Wave %d/%d: %s", wave_idx + 1, len(waves), wave)
            ProgressPublisher.publish_progress(
                f"workspace_{workspace_id}",
                "RUNNING",
                10 + int(70 * (repos_done / max(1, total_repos))),
                "WAVE_EXECUTION",
                f"Executing Wave {wave_idx + 1}/{len(waves)} ({len(wave)} repositories)",
            )

            for member_id in wave:
                member = manifest.get_repository(member_id)
                if not member:
                    continue

                with get_sync_db() as db_repo:
                    repo_entity = db_repo.query(Repository).filter(
                        (Repository.id == member.id) | (Repository.name == member.id)
                    ).first()
                    if not repo_entity:
                        repo_entity = Repository(
                            id=member.id,
                            name=member.id,
                            path=member.path,
                            description=f"Auto-registered workspace member {member.id}",
                        )
                        db_repo.add(repo_entity)
                        db_repo.commit()
                        db_repo.refresh(repo_entity)
                    actual_repo_id = repo_entity.id

                # Run pipeline
                pipeline = AnalysisPipeline()
                result = pipeline.run(
                    target_path=member.path,
                    repository_name=member.id,
                    mode="full",
                )
                repo_results[member.id] = result

                # Save repository snapshot
                with get_sync_db() as db_snap:
                    snap = PersistenceService.save_analysis_snapshot_sync(
                        db=db_snap,
                        repository_id=actual_repo_id,
                        result=result,
                    )
                    analysis_snapshot_ids.append(snap.id)

                # Publish contracts to FCR if available
                if hasattr(result, "contracts") and result.contracts:
                    federated_registry.publish_repository_contracts(member.id, result.contracts)

                repos_done += 1

        # 4. Fleet Compliance Rollup & Attestation
        evaluator = FleetComplianceEvaluator(manifest)
        suite = evaluator.aggregate_compliance(repo_results)
        secret_key = "codesentinel-enterprise-default-key"
        envelope = evaluator.generate_workspace_attestation(suite, secret_key=secret_key)

        # 5. Persist WorkspaceSnapshot and link members
        total_findings = sum(len(r.findings) for r in repo_results.values() if hasattr(r, "findings"))
        crit_findings = sum(
            len([f for f in r.findings if getattr(f.severity, "value", str(f.severity)).upper() == "CRITICAL"])
            for r in repo_results.values() if hasattr(r, "findings")
        )
        high_findings = sum(
            len([f for f in r.findings if getattr(f.severity, "value", str(f.severity)).upper() == "HIGH"])
            for r in repo_results.values() if hasattr(r, "findings")
        )

        with get_sync_db() as db_final:
            ws_snapshot = WorkspaceSnapshot(
                workspace_id=workspace_id,
                composite_health_score=suite.composite_health_score,
                composite_grade=suite.composite_grade,
                total_findings=total_findings,
                critical_findings=crit_findings,
                high_findings=high_findings,
                merkle_workspace_root=suite.workspace_merkle_root,
                attestation_envelope=envelope.model_dump(mode="json"),
                compliance_suite=suite.model_dump(mode="json"),
                repository_snapshot_ids=analysis_snapshot_ids,
            )
            db_final.add(ws_snapshot)
            db_final.flush()

            # Link member snapshots
            for snap_id in analysis_snapshot_ids:
                snap = db_final.query(AnalysisSnapshot).filter_by(id=snap_id).first()
                if snap:
                    snap.workspace_snapshot_id = ws_snapshot.id
            db_final.commit()
            snapshot_id = ws_snapshot.id

        ProgressPublisher.publish_progress(
            f"workspace_{workspace_id}",
            "COMPLETED",
            100,
            "COMPLETED",
            "Workspace scan completed successfully",
            snapshot_id=snapshot_id,
        )
        logger.info("Workspace %s scan completed successfully (snapshot: %s)", workspace_id, snapshot_id)
        return {"workspace_id": workspace_id, "snapshot_id": snapshot_id, "status": "COMPLETED"}

    except Exception as exc:
        logger.exception("Workspace scan %s failed: %s", workspace_id, exc)
        ProgressPublisher.publish_progress(
            f"workspace_{workspace_id}", "FAILED", 0, "FAILED", error_message=str(exc)
        )
        return {"workspace_id": workspace_id, "status": "FAILED", "error": str(exc)}
