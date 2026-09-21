"""Rule catalog and metadata endpoints for CodeSentinel API."""

from fastapi import APIRouter

from analyzer.rules.registry import RuleRegistry
from backend.app.core.exceptions import RuleNotFoundException
from backend.app.schemas.rules import RuleListResponse, RuleMetadataDTO

router = APIRouter()


@router.get(
    "/rules",
    response_model=RuleListResponse,
    summary="List registered analysis rules",
    description="Retrieve catalog of all registered security and architecture rules with their metadata.",
)
async def list_rules() -> RuleListResponse:
    """Return all registered analysis rules sorted deterministically by rule_id."""
    registry = RuleRegistry(load_defaults=True)
    rule_definitions = registry.get_rule_definitions()
    rule_definitions.sort(key=lambda r: r.rule_id)

    dtos = [
        RuleMetadataDTO(
            rule_id=r.rule_id,
            name=r.name,
            category=r.category.value if hasattr(r.category, "value") else str(r.category),
            evidence_type=r.evidence_type.value if hasattr(r.evidence_type, "value") else str(r.evidence_type),
            severity=r.severity.value if hasattr(r.severity, "value") else str(r.severity),
            confidence=r.confidence.value if hasattr(r.confidence, "value") else str(r.confidence),
            description=r.description,
            remediation=r.remediation,
            supported_languages=r.supported_languages,
            frameworks=r.frameworks,
            cwe_id=r.cwe_id,
            owasp_category=r.owasp_category,
            rationale=r.rationale,
        )
        for r in rule_definitions
    ]

    return RuleListResponse(total_rules=len(dtos), rules=dtos)


@router.get(
    "/rules/{rule_id}",
    response_model=RuleMetadataDTO,
    summary="Get rule details by ID",
    description="Retrieve detailed metadata for a specific security or architecture rule.",
)
async def get_rule(rule_id: str) -> RuleMetadataDTO:
    """Return detailed metadata for the specified rule_id, or raise 404 if not found."""
    registry = RuleRegistry(load_defaults=True)
    all_defs = registry.get_rule_definitions()
    target_def = next((r for r in all_defs if r.rule_id.lower() == rule_id.lower()), None)

    if not target_def:
        raise RuleNotFoundException(rule_id)

    return RuleMetadataDTO(
        rule_id=target_def.rule_id,
        name=target_def.name,
        category=target_def.category.value if hasattr(target_def.category, "value") else str(target_def.category),
        evidence_type=target_def.evidence_type.value if hasattr(target_def.evidence_type, "value") else str(target_def.evidence_type),
        severity=target_def.severity.value if hasattr(target_def.severity, "value") else str(target_def.severity),
        confidence=target_def.confidence.value if hasattr(target_def.confidence, "value") else str(target_def.confidence),
        description=target_def.description,
        remediation=target_def.remediation,
        supported_languages=target_def.supported_languages,
        frameworks=target_def.frameworks,
        cwe_id=target_def.cwe_id,
        owasp_category=target_def.owasp_category,
        rationale=target_def.rationale,
    )
