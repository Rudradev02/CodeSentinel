"""Compliance and governance API endpoints for CodeSentinel (Phase 26)."""

from typing import Any
from fastapi import APIRouter, HTTPException

from analyzer.compliance.catalogs import ALL_COMPLIANCE_CONTROLS, find_control_by_id
from analyzer.compliance.models import ComplianceFramework
from analyzer.compliance.attestation import (
    VerifiableAttestationEnvelope,
    verify_attestation,
)
from analyzer.rules.pack_resolver import RulePackResolver
from backend.app.schemas.compliance import (
    AttestationVerifyRequest,
    AttestationVerifyResponse,
    ComplianceControlDTO,
)

router = APIRouter()


@router.get("/frameworks", response_model=list[dict[str, Any]])
def list_compliance_frameworks():
    """List supported regulatory compliance frameworks and their control counts."""
    frameworks_info = []
    for fw, controls in ALL_COMPLIANCE_CONTROLS.items():
        frameworks_info.append({
            "framework_id": fw.value,
            "name": fw.name,
            "total_controls": len(controls),
            "critical_controls": len([c for c in controls if c.criticality.value in ("CRITICAL", "HIGH")]),
        })
    return frameworks_info


@router.get("/frameworks/{framework_id}/controls", response_model=list[ComplianceControlDTO])
def get_framework_controls(framework_id: str):
    """Retrieve all controls for a specific regulatory standard."""
    norm_id = framework_id.strip().upper().replace("-", "_")
    target_fw = None
    for fw in ComplianceFramework:
        if fw.value == norm_id or fw.name == norm_id:
            target_fw = fw
            break

    if not target_fw:
        valid_fws = [f.value for f in ComplianceFramework]
        raise HTTPException(
            status_code=404,
            detail=f"Compliance framework '{framework_id}' not found. Supported: {valid_fws}",
        )

    controls = ALL_COMPLIANCE_CONTROLS.get(target_fw, [])
    return [
        ComplianceControlDTO(
            control_id=c.control_id,
            framework=c.framework.value,
            name=c.name,
            section=c.section,
            description=c.description,
            criticality=c.criticality.value,
            guidance=c.guidance,
            mapped_rule_ids=c.mapped_rule_ids,
            mapped_policy_ids=c.mapped_policy_ids,
            framework_version=getattr(c, "framework_version", "1.0"),
            mapping_type=c.mapping_type.value if hasattr(getattr(c, "mapping_type", None), "value") else (str(c.mapping_type) if getattr(c, "mapping_type", None) else None),
            static_limitations=getattr(c, "static_limitations", []) or [],
            provenance=c.provenance.model_dump(mode="json") if getattr(c, "provenance", None) else None,
        )
        for c in controls
    ]


@router.get("/packs", response_model=list[dict[str, Any]])
def list_rule_packs():
    """List registered and built-in enterprise rule packs."""
    resolver = RulePackResolver()
    packs_info = []
    for pid, pack in resolver._packs.items():
        packs_info.append({
            "pack_id": pack.pack_id,
            "version": pack.version,
            "name": pack.name,
            "description": pack.description,
            "extends": pack.extends,
            "compliance_frameworks": [f.value for f in pack.compliance_frameworks],
            "rule_overrides_count": len(pack.rule_overrides),
            "disallow_inline_suppressions": pack.disallow_inline_suppressions,
            "allow_repo_override": pack.allow_repo_override,
        })
    return packs_info


@router.post("/verify-attestation", response_model=AttestationVerifyResponse)
def verify_scan_attestation(request: AttestationVerifyRequest):
    """Verify cryptographic authenticity of an in-toto / DSSE scan attestation envelope."""
    envelope = VerifiableAttestationEnvelope(
        payload=request.payload,
        payloadType=request.payloadType,
        signatures=request.signatures,
    )
    is_valid, msg, stmt = verify_attestation(envelope, request.secret_key)
    stmt_dict = stmt.model_dump(exclude_none=True) if stmt else None

    return AttestationVerifyResponse(
        is_valid=is_valid,
        message=msg,
        statement=stmt_dict,
    )
