"""Natural-language policy parsing, schema validation, and semantic verification for Phase 30.

Translates candidate policy proposals into validated, strongly-typed SecurityPolicy models.
Rejects vague, contradictory, or unsupported policies before human approval and activation.
"""

from enum import Enum
import json
import logging
import re
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from analyzer.dataflow.properties import SecurityProperty
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.boundary import TrustBoundaryType
from analyzer.models.findings import FindingSeverity
from analyzer.rules.policy import PolicyEnforcementMode, SecurityPolicy

logger = logging.getLogger(__name__)


VAGUE_TERMS = [
    "secure",
    "safe",
    "completely secure",
    "bulletproof",
    "hack-proof",
    "clean",
    "good",
    "protected",
]

# Standard allowed sanitizers across Python, JS/TS, and Go
STANDARD_KNOWN_SANITIZERS = {
    # Python
    "int",
    "float",
    "shlex.quote",
    "html.escape",
    "psycopg2.sql.Literal",
    "quote",
    # JavaScript / TypeScript
    "DOMPurify.sanitize",
    "sanitizeHtml",
    "escape",
    "encodeURIComponent",
    # Go
    "strconv.Atoi",
    "strconv.ParseInt",
    "html.EscapeString",
    "url.QueryEscape",
}


class PolicyValidationStatus(str, Enum):
    VALIDATED_CANDIDATE = "VALIDATED_CANDIDATE"
    UNKNOWN_OR_AMBIGUOUS = "UNKNOWN_OR_AMBIGUOUS"
    CONTRADICTORY = "CONTRADICTORY"
    INVALID_SCHEMA = "INVALID_SCHEMA"


class SecurityPolicyCandidateDTO(BaseModel):
    """Pydantic transfer model for AI-generated candidate security policies."""

    model_config = ConfigDict(extra="ignore")

    policy_id: str = Field(..., description="Unique policy identifier (e.g. POL-SQL-02)")
    name: str = Field(..., min_length=4, max_length=255)
    description: str = Field(..., min_length=8)
    source_boundaries: list[str] = Field(default_factory=list)
    target_sink_categories: list[str] = Field(min_length=1)
    required_security_properties: list[str] = Field(default_factory=list)
    allowed_sanitizers: list[str] = Field(default_factory=list)
    require_authentication: bool = False
    require_authorization: bool = False
    enforcement_mode: str = "ADVISORY"
    associated_rule_ids: list[str] = Field(default_factory=list)
    severity: str = "HIGH"

    @field_validator("policy_id")
    @classmethod
    def validate_policy_id_format(cls, v: str) -> str:
        clean = v.strip().upper()
        if not re.match(r"^POL-[A-Z0-9\-_]+$", clean):
            raise ValueError(f"policy_id '{v}' must match format POL-[A-Z0-9-_]+")
        return clean


# Canonical synonyms mapping common NL/LLM terminology to exact CodeSentinel enums
SECURITY_PROPERTY_SYNONYMS: dict[str, SecurityProperty] = {
    "SQL_PARAMETRIZED": SecurityProperty.SQL_SAFE,
    "SQL_PARAMETERIZED": SecurityProperty.SQL_SAFE,
    "SQL_PARAM": SecurityProperty.SQL_SAFE,
    "SQL_SAFE": SecurityProperty.SQL_SAFE,
    "SHELL_ESCAPED": SecurityProperty.SHELL_QUOTED,
    "SHELL_QUOTED": SecurityProperty.SHELL_QUOTED,
    "COMMAND_SAFE": SecurityProperty.COMMAND_SAFE,
    "HTML_ESCAPED": SecurityProperty.HTML_ESCAPED,
    "HTML_SAFE": SecurityProperty.HTML_SAFE,
    "URL_ENCODED": SecurityProperty.URL_SAFE,
    "URL_SAFE": SecurityProperty.URL_SAFE,
    "PATH_CANONICALIZED": SecurityProperty.PATH_NORMALIZED,
    "PATH_NORMALIZED": SecurityProperty.PATH_NORMALIZED,
    "PATH_SAFE": SecurityProperty.PATH_SAFE,
    "TYPE_COERCED_INT": SecurityProperty.TYPE_COERCED,
    "TYPE_COERCED_FLOAT": SecurityProperty.TYPE_COERCED,
    "TYPE_COERCED": SecurityProperty.TYPE_COERCED,
    "VALIDATED_TYPE": SecurityProperty.VALIDATED_TYPE,
    "AUTHENTICATED": SecurityProperty.AUTHENTICATED,
    "AUTHORIZED": SecurityProperty.AUTHORIZED,
}

SINK_CATEGORY_SYNONYMS: dict[str, SinkCategory] = {
    "SQL_EXECUTE": SinkCategory.SQL_EXECUTE,
    "SQL_INJECTION": SinkCategory.SQL_EXECUTE,
    "COMMAND_EXECUTE": SinkCategory.COMMAND_EXECUTE,
    "COMMAND_INJECTION": SinkCategory.COMMAND_EXECUTE,
    "CODE_EVAL": SinkCategory.CODE_EVAL,
    "CODE_EXECUTION": SinkCategory.CODE_EVAL,
    "DOM_INJECTION": SinkCategory.DOM_INJECTION,
    "XSS": SinkCategory.DOM_INJECTION,
    "FILE_PATH": SinkCategory.FILE_PATH,
    "PATH_TRAVERSAL": SinkCategory.FILE_PATH,
}

TRUST_BOUNDARY_SYNONYMS: dict[str, TrustBoundaryType] = {
    "HTTP_REQUEST_PARAM": TrustBoundaryType.HTTP_REQUEST_PARAM,
    "HTTP_REQUEST_BODY": TrustBoundaryType.HTTP_REQUEST_BODY,
    "HTTP_REQUEST_HEADER": TrustBoundaryType.HTTP_REQUEST_HEADER,
    "HTTP_COOKIE": TrustBoundaryType.HTTP_COOKIE,
    "ENVIRONMENT_VARIABLE": TrustBoundaryType.ENVIRONMENT_VARIABLE,
    "CLI_ARGUMENT": TrustBoundaryType.CLI_ARGUMENT,
    "DOM_INPUT": TrustBoundaryType.DOM_INPUT,
    "EXTERNAL_API": TrustBoundaryType.EXTERNAL_API,
    "INTERNAL_SERVICE": TrustBoundaryType.INTERNAL_SERVICE,
    "PUBLIC_INTERNET_UNAUTHENTICATED": TrustBoundaryType.HTTP_REQUEST_PARAM,
}


class SemanticPolicyValidator:
    """Verifies that an AI-generated policy candidate adheres to CodeSentinel's semantic domains."""

    @classmethod
    def validate(
        cls,
        candidate_json: dict[str, Any],
        raw_prompt: str = "",
    ) -> tuple[PolicyValidationStatus, Optional[SecurityPolicy], list[str]]:
        """Validate candidate JSON against deterministic constraints.

        Returns:
            Tuple of (status, validated_SecurityPolicy_or_None, diagnostic_messages)
        """
        diagnostics: list[str] = []

        # 1. Check for vague/unoperational terms in prompt or description
        combined_text = (raw_prompt + " " + str(candidate_json.get("description", ""))).lower()
        for term in VAGUE_TERMS:
            # Check if term is used standalone rather than mapped to specific property
            if re.search(rf"\b{re.escape(term)}\b", combined_text):
                # Verify whether actual concrete sink and property were provided
                sinks = candidate_json.get("target_sink_categories", [])
                props = candidate_json.get("required_security_properties", [])
                if not sinks or not props:
                    diagnostics.append(
                        f"Vague directive '{term}' does not map to an operational SecurityProperty or SinkCategory."
                    )
                    return PolicyValidationStatus.UNKNOWN_OR_AMBIGUOUS, None, diagnostics

        # 2. Schema validation
        try:
            dto = SecurityPolicyCandidateDTO.model_validate(candidate_json)
        except Exception as exc:
            diagnostics.append(f"Schema validation error: {exc}")
            return PolicyValidationStatus.INVALID_SCHEMA, None, diagnostics

        # 3. Contradiction Detection
        # Demanding authentication while explicitly specifying only unauthenticated boundaries
        if dto.require_authentication and any("UNAUTHENTICATED" in b.upper() or "ANONYMOUS" in b.upper() for b in dto.source_boundaries):
            diagnostics.append("Contradictory policy: Demands authentication but restricts sources to unauthenticated boundaries.")
            return PolicyValidationStatus.CONTRADICTORY, None, diagnostics

        # 4. Enum domain validation
        # Sink Categories
        resolved_sinks: list[SinkCategory] = []
        for s in dto.target_sink_categories:
            s_clean = s.upper()
            if s_clean in SINK_CATEGORY_SYNONYMS:
                resolved_sinks.append(SINK_CATEGORY_SYNONYMS[s_clean])
            else:
                try:
                    resolved_sinks.append(SinkCategory(s_clean))
                except ValueError:
                    diagnostics.append(f"Target sink category '{s}' is not a recognized SinkCategory.")

        # Trust Boundaries
        resolved_boundaries: list[TrustBoundaryType] = []
        for b in dto.source_boundaries:
            b_clean = b.upper()
            if b_clean in TRUST_BOUNDARY_SYNONYMS:
                resolved_boundaries.append(TRUST_BOUNDARY_SYNONYMS[b_clean])
            else:
                try:
                    resolved_boundaries.append(TrustBoundaryType(b_clean))
                except ValueError:
                    diagnostics.append(f"Source boundary '{b}' is not a recognized TrustBoundaryType.")

        # Security Properties
        resolved_properties: list[SecurityProperty] = []
        for p in dto.required_security_properties:
            p_clean = p.upper()
            if p_clean in SECURITY_PROPERTY_SYNONYMS:
                resolved_properties.append(SECURITY_PROPERTY_SYNONYMS[p_clean])
            else:
                try:
                    resolved_properties.append(SecurityProperty(p_clean))
                except ValueError:
                    diagnostics.append(f"Security property '{p}' is not a recognized SecurityProperty.")

        # Severity
        try:
            resolved_severity = FindingSeverity(dto.severity.upper())
        except ValueError:
            diagnostics.append(f"Severity '{dto.severity}' is invalid. Allowed: CRITICAL, HIGH, MEDIUM, LOW, INFO.")
            resolved_severity = FindingSeverity.HIGH

        # Enforcement Mode
        try:
            resolved_mode = PolicyEnforcementMode(dto.enforcement_mode.upper())
        except ValueError:
            diagnostics.append(f"Enforcement mode '{dto.enforcement_mode}' is invalid.")
            resolved_mode = PolicyEnforcementMode.ADVISORY

        # 5. Sanitizer compatibility check
        for san in dto.allowed_sanitizers:
            clean_san = san.strip()
            if clean_san not in STANDARD_KNOWN_SANITIZERS and not any(clean_san.endswith(f".{k}") for k in STANDARD_KNOWN_SANITIZERS):
                diagnostics.append(f"Sanitizer '{san}' is not in the recognized sanitizer registry.")

        if diagnostics:
            return PolicyValidationStatus.UNKNOWN_OR_AMBIGUOUS, None, diagnostics

        # 6. Instantiate canonical SecurityPolicy
        policy = SecurityPolicy(
            policy_id=dto.policy_id,
            version=1,
            name=dto.name,
            description=dto.description,
            source_boundaries=resolved_boundaries,
            target_sink_categories=resolved_sinks,
            required_security_properties=resolved_properties,
            allowed_sanitizers=dto.allowed_sanitizers,
            require_authentication=dto.require_authentication,
            require_authorization=dto.require_authorization,
            enforcement_mode=resolved_mode,
            associated_rule_ids=dto.associated_rule_ids,
            severity=resolved_severity,
        )

        return PolicyValidationStatus.VALIDATED_CANDIDATE, policy, ["Policy verified successfully against semantic grammar."]
