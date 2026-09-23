"""AI Enrichment Orchestration Service.

Coordinates bounded context extraction, secret scrubbing, prompt assembly,
LLM provider execution, semantic validation, and PostgreSQL persistence.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models.ai_enrichment import AIEnrichmentRecord
from backend.app.models.finding import FindingSnapshot
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.services.ai.context_builder import ContextBuilder
from backend.app.services.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from backend.app.services.ai.providers.base import BaseLLMProvider
from backend.app.services.ai.providers.ollama import OllamaProvider
from backend.app.services.ai.providers.openrouter import OpenRouterProvider
from backend.app.services.ai.scrubber import SecretScrubber
from backend.app.services.ai.validator import SemanticValidator

logger = logging.getLogger(__name__)


class AIEnrichmentOrchestrator:
    """Coordinates end-to-end AI triage and remediation pipeline."""

    @classmethod
    def get_provider(
        cls,
        provider_name: Optional[str] = None,
        model_name: Optional[str] = None,
    ) -> tuple[BaseLLMProvider, str, str]:
        """Instantiate configured LLM provider and determine target model."""
        settings = get_settings()
        selected_provider = (provider_name or settings.AI_PROVIDER).lower()

        if selected_provider == "ollama":
            model = model_name or settings.OLLAMA_MODEL
            provider = OllamaProvider(
                base_url=settings.OLLAMA_BASE_URL,
                default_model=model,
                connect_timeout=5.0,
                generate_timeout=float(settings.AI_TIMEOUT_SECONDS),
            )
            return provider, "ollama", model
        else:
            model = model_name or settings.OPENROUTER_MODEL
            provider = OpenRouterProvider(
                api_key=settings.OPENROUTER_API_KEY,
                base_url=settings.OPENROUTER_BASE_URL,
                default_model=model,
                timeout=float(settings.AI_TIMEOUT_SECONDS),
                max_retries=settings.AI_MAX_RETRIES,
            )
            return provider, "openrouter", model

    @classmethod
    def enrich_finding_sync(
        cls,
        db: Session,
        finding_id: str,
        provider_name: Optional[str] = None,
        model_name: Optional[str] = None,
        force_refresh: bool = False,
    ) -> AIEnrichmentRecord:
        """Run complete AI enrichment workflow synchronously for worker or API execution."""
        settings = get_settings()

        # 1. Fetch Finding and Parent Snapshot
        finding = db.query(FindingSnapshot).filter_by(id=finding_id).first()
        if not finding:
            raise ValueError(f"FindingSnapshot '{finding_id}' not found.")

        snapshot = db.query(AnalysisSnapshot).filter_by(id=finding.snapshot_id).first()
        if not snapshot:
            raise ValueError(f"Parent AnalysisSnapshot '{finding.snapshot_id}' not found.")

        repo = db.query(Repository).filter_by(id=snapshot.repository_id).first()
        if not repo:
            raise ValueError(f"Parent Repository '{snapshot.repository_id}' not found.")

        provider, prov_name, target_model = cls.get_provider(provider_name, model_name)
        prompt_version = "v1"

        # 2. Check Database Cache / Deduplication
        existing_record = (
            db.query(AIEnrichmentRecord)
            .filter_by(
                finding_id=finding.id,
                provider=prov_name,
                model=target_model,
                prompt_version=prompt_version,
            )
            .first()
        )

        if existing_record and existing_record.status == "COMPLETED" and not force_refresh:
            logger.info("Found cached AI enrichment record %s for finding %s", existing_record.id, finding.id)
            return existing_record

        record = existing_record
        if not record:
            record = AIEnrichmentRecord(
                finding_id=finding.id,
                snapshot_id=snapshot.id,
                repository_id=repo.id,
                status="RUNNING",
                provider=prov_name,
                model=target_model,
                prompt_version=prompt_version,
            )
            db.add(record)
            db.commit()
            db.refresh(record)
        else:
            record.status = "RUNNING"
            record.error_message = None
            db.commit()

        # Check if AI is globally disabled
        if not settings.AI_ENABLED and not force_refresh:
            record.status = "DISABLED"
            record.error_message = "AI enrichment is disabled in configuration (AI_ENABLED=False)."
            record.completed_at = datetime.now(timezone.utc)
            db.commit()
            return record

        try:
            # 3. Extract Bounded AST Context
            repo_path = Path(repo.path)
            raw_context = ContextBuilder.extract_context(
                repo_root=repo_path,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                language=finding.language,
            )

            # 4. Pre-Prompt Secret Scrubbing
            scrubbed_source = SecretScrubber.scrub(raw_context.enclosing_source)
            scrubbed_imports = [SecretScrubber.scrub(imp) for imp in raw_context.relevant_imports]
            scrubbed_snippet = SecretScrubber.scrub(finding.snippet)
            scrubbed_message = SecretScrubber.scrub(finding.message)

            # 5. Assemble Prompt Envelope
            user_prompt = build_user_prompt(
                finding_id=finding.id,
                rule_id=finding.rule_id,
                rule_name=finding.rule_name,
                severity=finding.severity,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                message=scrubbed_message,
                description=finding.description,
                deterministic_remediation=finding.remediation,
                enclosing_symbol_name=raw_context.enclosing_symbol_name,
                enclosing_symbol_kind=raw_context.enclosing_symbol_kind,
                enclosing_source=scrubbed_source,
                relevant_imports=scrubbed_imports,
            )

            # 6. Execute Provider Inference
            llm_response = provider.generate_sync(
                prompt=user_prompt,
                system_prompt=SYSTEM_PROMPT,
                model=target_model,
            )

            if not llm_response.parsed_json:
                raise ValueError("Model response could not be parsed as valid JSON.")

            # 7. Semantic Validation Gate
            validated_dto = SemanticValidator.validate_and_sanitize(
                raw_json=llm_response.parsed_json,
                target_finding_id=finding.id,
                target_file_path=finding.file_path,
                repo_root=repo_path,
            )

            # 8. Update Record with Validated Results
            record.status = "COMPLETED"
            record.is_likely_true_positive = validated_dto.is_likely_true_positive
            record.confidence_score = validated_dto.confidence_score
            record.risk_summary = validated_dto.risk_summary
            record.technical_reasoning = validated_dto.technical_reasoning
            record.assumptions_limitations = {"items": validated_dto.assumptions_and_limitations}
            record.prescribed_remediation = validated_dto.prescribed_remediation
            record.proposed_patch = (
                validated_dto.proposed_patch.model_dump() if validated_dto.proposed_patch else None
            )
            record.raw_response = llm_response.parsed_json
            record.completed_at = datetime.now(timezone.utc)

            # Update finding's ai_validation_status flag
            finding.ai_validation_status = (
                "TRUE_POSITIVE" if validated_dto.is_likely_true_positive else "FALSE_POSITIVE"
            )

            db.commit()
            db.refresh(record)
            logger.info("Successfully completed AI enrichment %s for finding %s", record.id, finding.id)
            return record

        except Exception as exc:
            logger.exception("AI enrichment failed for finding %s: %s", finding.id, exc)
            record.status = "FAILED"
            record.error_message = str(exc)
            record.completed_at = datetime.now(timezone.utc)
            db.commit()
            return record
