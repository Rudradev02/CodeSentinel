"""Centralized enterprise rule pack and suppression policy distribution service (Phase 28)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from analyzer.rules.pack_resolver import (
    MonotonicPolicyViolationError,
    RulePackResolver,
)
from analyzer.rules.rule_pack import RuleOverride, RulePack
from backend.app.models.policy import CentralizedRulePack, CentralizedSuppression


class CentralPolicyDistributionService:
    """Manages organization-wide rule packs and auditable suppression exceptions."""

    MAX_SUPPRESSION_DAYS = 180

    @classmethod
    def register_rule_pack(
        cls,
        db: Session,
        organization_id: str,
        pack_yaml: str,
    ) -> CentralizedRulePack:
        """Parse, validate, hash, and persist an organizational rule pack."""
        resolver = RulePackResolver()
        pack = resolver.load_pack_from_yaml(pack_yaml)

        # Compute pack hash
        resolved_config = resolver.resolve_packs([pack.pack_id])
        canonical_hash = resolved_config.resolved_pack_hash

        record = CentralizedRulePack(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            pack_id=pack.pack_id,
            version=pack.version,
            name=pack.name,
            pack_yaml=pack_yaml,
            pack_hash=canonical_hash,
            created_at=datetime.now(timezone.utc),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @classmethod
    def get_organization_rule_packs(
        cls,
        db: Session,
        organization_id: str,
    ) -> list[CentralizedRulePack]:
        """Fetch all active rule packs registered for an organization."""
        return (
            db.query(CentralizedRulePack)
            .filter_by(organization_id=organization_id)
            .order_by(CentralizedRulePack.pack_id)
            .all()
        )

    @classmethod
    def register_suppression(
        cls,
        db: Session,
        organization_id: str,
        rule_id: str,
        justification: str,
        compensating_control: str,
        approved_by: str,
        ticket_reference: str,
        expires_at: datetime,
        target_repo_id: str = "*",
        target_file_pattern: str = "*",
        fingerprint_hash: Optional[str] = None,
    ) -> CentralizedSuppression:
        """Create an auditable, time-bound enterprise suppression exception."""
        clean_ticket = ticket_reference.strip()
        if not clean_ticket:
            raise ValueError("Centralized suppression requires an auditable ticket_reference (e.g. JIRA-1234)")

        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= now:
            raise ValueError("Suppression expiration date must be in the future")

        if expires_at > (now + timedelta(days=cls.MAX_SUPPRESSION_DAYS)):
            raise ValueError(f"Suppression duration cannot exceed {cls.MAX_SUPPRESSION_DAYS} days")

        supp = CentralizedSuppression(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            rule_id=rule_id.strip(),
            target_repo_id=target_repo_id.strip(),
            target_file_pattern=target_file_pattern.strip(),
            fingerprint_hash=fingerprint_hash.strip() if fingerprint_hash else None,
            justification=justification.strip(),
            compensating_control=compensating_control.strip(),
            approved_by=approved_by.strip(),
            ticket_reference=clean_ticket,
            created_at=now,
            expires_at=expires_at,
        )
        db.add(supp)
        db.commit()
        db.refresh(supp)
        return supp

    @classmethod
    def get_active_suppressions(
        cls,
        db: Session,
        organization_id: str,
        repository_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> list[CentralizedSuppression]:
        """Fetch active, unexpired suppressions applicable to an organization or repository."""
        ref_now = now or datetime.now(timezone.utc)
        query = (
            db.query(CentralizedSuppression)
            .filter(
                CentralizedSuppression.organization_id == organization_id,
                CentralizedSuppression.expires_at > ref_now,
            )
        )
        if repository_id:
            query = query.filter(
                (CentralizedSuppression.target_repo_id == "*") |
                (CentralizedSuppression.target_repo_id == repository_id)
            )
        return query.order_by(CentralizedSuppression.created_at.desc()).all()

    @classmethod
    def verify_monotonic_inheritance(
        cls,
        parent_pack: RulePack,
        child_pack: RulePack,
    ) -> None:
        """Verify that child pack does not violate monotonic invariants established by parent."""
        resolver = RulePackResolver()
        resolver.register_pack(parent_pack)
        resolver.register_pack(child_pack)
        # Attempt resolution; will raise MonotonicPolicyViolationError if illegal relaxation occurs
        resolver.resolve_packs([child_pack.pack_id])
