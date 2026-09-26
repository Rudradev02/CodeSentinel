"""Declarative security policy models and registry for CodeSentinel (Phase 23).

Evaluates contextual security invariants along data-flow paths connecting
trust boundaries to sensitive sink operations.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from analyzer.dataflow.properties import SecurityProperty, SecurityPropertyState
from analyzer.dataflow.taint.models import SinkCategory
from analyzer.models.boundary import AuthenticationState, AuthorizationState, TrustBoundaryType
from analyzer.models.findings import FindingSeverity


class PolicyEnforcementMode(str, Enum):
    """Execution and alerting mode for a security policy."""
    ENFORCE = "ENFORCE"    # Violations produce standard security findings
    ADVISORY = "ADVISORY"  # Violations produce informational findings
    DISABLED = "DISABLED"  # Policy is skipped during analysis


class PolicyEvaluationResult(str, Enum):
    """Result of evaluating a security policy over a data-flow trace."""
    PROVEN_VIOLATION = "PROVEN_VIOLATION"
    PROVEN_SAFE = "PROVEN_SAFE"
    UNKNOWN = "UNKNOWN"
    # Aliases
    VIOLATED = "PROVEN_VIOLATION"
    SATISFIED = "PROVEN_SAFE"


from analyzer.models.obligation import (
    ObligationKind,
    ObligationEvaluationState,
    PolicyProofObligation,
)


class PolicyEvaluationOutcome(BaseModel):
    """Summary of a single policy evaluation execution."""
    model_config = ConfigDict(frozen=True)

    result: PolicyEvaluationResult
    satisfied_properties: list[str] = Field(default_factory=list)
    missing_properties: list[str] = Field(default_factory=list)
    explanation: str = ""
    proof_obligations: list[PolicyProofObligation] = Field(default_factory=list)
    unknown_reasons: list[str] = Field(default_factory=list)


class SecurityPolicy(BaseModel):
    """Declarative specification of an end-to-end security invariant."""
    model_config = ConfigDict(frozen=True)

    policy_id: str
    version: int = 1
    name: str
    description: str
    source_boundaries: list[TrustBoundaryType] = Field(default_factory=list)
    target_sink_categories: list[SinkCategory] = Field(default_factory=list)
    required_security_properties: list[SecurityProperty] = Field(default_factory=list)
    allowed_sanitizers: list[str] = Field(default_factory=list)
    require_authentication: bool = False
    require_authorization: bool = False
    enforcement_mode: PolicyEnforcementMode = PolicyEnforcementMode.ENFORCE
    associated_rule_ids: list[str] = Field(default_factory=list)
    severity: FindingSeverity = FindingSeverity.HIGH

    def generate_proof_obligations(
        self,
        sink_category: SinkCategory,
        file_path: str = "",
        line: int = 0,
        target_expression: str = "",
    ) -> list[PolicyProofObligation]:
        """Generate unfilled proof obligations required by this policy."""
        obligations: list[PolicyProofObligation] = []
        if self.require_authentication:
            obligations.append(
                PolicyProofObligation(
                    obligation_id=f"OBL_AUTH_{self.policy_id}_{line}",
                    policy_id=self.policy_id,
                    kind=ObligationKind.REQUIRES_AUTHENTICATION,
                    target_sink_category=sink_category,
                    file_path=file_path,
                    line=line,
                    target_expression=target_expression,
                )
            )
        if self.require_authorization:
            obligations.append(
                PolicyProofObligation(
                    obligation_id=f"OBL_AUTHZ_{self.policy_id}_{line}",
                    policy_id=self.policy_id,
                    kind=ObligationKind.REQUIRES_AUTHORIZATION,
                    target_sink_category=sink_category,
                    file_path=file_path,
                    line=line,
                    target_expression=target_expression,
                )
            )
        for req_prop in self.required_security_properties:
            obligations.append(
                PolicyProofObligation(
                    obligation_id=f"OBL_PROP_{self.policy_id}_{req_prop.value}_{line}",
                    policy_id=self.policy_id,
                    kind=ObligationKind.REQUIRES_PROPERTY,
                    target_sink_category=sink_category,
                    required_property=req_prop,
                    file_path=file_path,
                    line=line,
                    target_expression=target_expression,
                )
            )
        return obligations

    def evaluate(
        self,
        sink_category: Optional[SinkCategory] = None,
        property_state: Optional[SecurityPropertyState] = None,
        auth_state: AuthenticationState = AuthenticationState.UNKNOWN,
        authz_state: AuthorizationState = AuthorizationState.UNKNOWN,
        sanitizer_id: Optional[str] = None,
    ) -> PolicyEvaluationOutcome:
        """Evaluate if the provided property state and context satisfies this policy."""
        state = property_state or SecurityPropertyState()
        satisfied: list[str] = []
        missing: list[str] = []
        obligations: list[PolicyProofObligation] = []
        unknown_reasons: list[str] = []
        sink_target = sink_category or (self.target_sink_categories[0] if self.target_sink_categories else SinkCategory.SQL_EXECUTE)

        # 1. Authentication check
        if self.require_authentication:
            if auth_state == AuthenticationState.AUTHENTICATED:
                satisfied.append("AUTHENTICATED")
                obl_state = ObligationEvaluationState.PROVEN_SAFE
                obl_detail = "Verified identity established via authentication decorator/middleware"
                unk_reason = None
            elif auth_state == AuthenticationState.UNAUTHENTICATED:
                missing.append("AUTHENTICATED (Unauthenticated caller)")
                obl_state = ObligationEvaluationState.PROVEN_VIOLATION
                obl_detail = "Caller is unauthenticated"
                unk_reason = None
            else:
                missing.append("AUTHENTICATED (Unknown authentication context)")
                obl_state = ObligationEvaluationState.UNKNOWN
                obl_detail = "Indeterminate authentication context"
                unk_reason = "No structural authentication check dominating path"
                unknown_reasons.append(unk_reason)

            obligations.append(
                PolicyProofObligation(
                    obligation_id=f"OBL_AUTH_{self.policy_id}",
                    policy_id=self.policy_id,
                    kind=ObligationKind.REQUIRES_AUTHENTICATION,
                    target_sink_category=sink_target,
                    state=obl_state,
                    evidence_details=obl_detail,
                    unknown_reason=unk_reason,
                )
            )

        # 2. Authorization check
        if self.require_authorization:
            if authz_state in (AuthorizationState.AUTHORIZED, AuthorizationState.ROLE_VERIFIED, AuthorizationState.PERMISSION_GRANTED):
                satisfied.append("AUTHORIZED")
                obl_state = ObligationEvaluationState.PROVEN_SAFE
                obl_detail = f"Verified authorization: {authz_state.value}"
                unk_reason = None
            elif authz_state == AuthorizationState.UNAUTHORIZED:
                missing.append("AUTHORIZED (Unauthorized caller)")
                obl_state = ObligationEvaluationState.PROVEN_VIOLATION
                obl_detail = "Caller lacks required permission/role"
                unk_reason = None
            else:
                missing.append("AUTHORIZED (Unknown authorization context)")
                obl_state = ObligationEvaluationState.UNKNOWN
                obl_detail = "Indeterminate authorization context"
                unk_reason = "No dominating permission or role check dominating path"
                unknown_reasons.append(unk_reason)

            obligations.append(
                PolicyProofObligation(
                    obligation_id=f"OBL_AUTHZ_{self.policy_id}",
                    policy_id=self.policy_id,
                    kind=ObligationKind.REQUIRES_AUTHORIZATION,
                    target_sink_category=sink_target,
                    state=obl_state,
                    evidence_details=obl_detail,
                    unknown_reason=unk_reason,
                )
            )

        # 3. Allowed Sanitizer check
        if sanitizer_id and self.allowed_sanitizers:
            san_lower = sanitizer_id.lower()
            if any(san_lower == allowed.lower() or san_lower.endswith(f".{allowed.lower()}") for allowed in self.allowed_sanitizers):
                satisfied.append(f"SANITIZER_{sanitizer_id}")
                obligations.append(
                    PolicyProofObligation(
                        obligation_id=f"OBL_SAN_{self.policy_id}_{sanitizer_id}",
                        policy_id=self.policy_id,
                        kind=ObligationKind.REQUIRES_SANITIZER,
                        target_sink_category=sink_target,
                        state=ObligationEvaluationState.PROVEN_SAFE,
                        evidence_details=f"Compatible sanitizer '{sanitizer_id}' applied",
                    )
                )
                return PolicyEvaluationOutcome(
                    result=PolicyEvaluationResult.SATISFIED,
                    satisfied_properties=satisfied,
                    missing_properties=[],
                    explanation=f"Policy {self.policy_id} satisfied via compatible sanitizer '{sanitizer_id}'",
                    proof_obligations=obligations,
                    unknown_reasons=unknown_reasons,
                )

        # 4. Required Security Properties check
        for req_prop in self.required_security_properties:
            if state.has_property(req_prop):
                satisfied.append(req_prop.value)
                obl_state = ObligationEvaluationState.PROVEN_SAFE
                obl_detail = f"Property {req_prop.value} verified"
                unk_reason = None
            elif SecurityProperty.UNKNOWN in state.properties:
                missing.append(req_prop.value)
                obl_state = ObligationEvaluationState.UNKNOWN
                obl_detail = f"Property {req_prop.value} indeterminate due to UNKNOWN state"
                unk_reason = "Unresolved abstract interpretation or dataflow truncation"
                unknown_reasons.append(unk_reason)
            else:
                missing.append(req_prop.value)
                obl_state = ObligationEvaluationState.PROVEN_VIOLATION
                obl_detail = f"Missing required property: {req_prop.value}"
                unk_reason = None

            obligations.append(
                PolicyProofObligation(
                    obligation_id=f"OBL_PROP_{self.policy_id}_{req_prop.value}",
                    policy_id=self.policy_id,
                    kind=ObligationKind.REQUIRES_PROPERTY,
                    target_sink_category=sink_target,
                    required_property=req_prop,
                    state=obl_state,
                    evidence_details=obl_detail,
                    unknown_reason=unk_reason,
                )
            )

        if missing:
            return PolicyEvaluationOutcome(
                result=PolicyEvaluationResult.VIOLATED,
                satisfied_properties=satisfied,
                missing_properties=missing,
                explanation=f"Policy {self.policy_id} violated. Missing required properties: {', '.join(missing)}",
                proof_obligations=obligations,
                unknown_reasons=unknown_reasons,
            )

        return PolicyEvaluationOutcome(
            result=PolicyEvaluationResult.SATISFIED,
            satisfied_properties=satisfied,
            missing_properties=[],
            explanation=f"Policy {self.policy_id} satisfied with properties: {', '.join(satisfied)}",
            proof_obligations=obligations,
            unknown_reasons=unknown_reasons,
        )


class SecurityPolicyRegistry:
    """Registry maintaining active security policies and evaluating policy compliance."""

    def __init__(self, load_defaults: bool = True):
        self._policies: dict[str, SecurityPolicy] = {}
        if load_defaults:
            self._load_defaults()

    def register_policy(self, policy: SecurityPolicy) -> None:
        self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> Optional[SecurityPolicy]:
        return self._policies.get(policy_id)

    def get_all_policies(self) -> list[SecurityPolicy]:
        return list(self._policies.values())

    def get_applicable_policies(
        self,
        boundary_type: Optional[TrustBoundaryType] = None,
        sink_category: Optional[SinkCategory] = None,
        rule_id: Optional[str] = None,
    ) -> list[SecurityPolicy]:
        applicable: list[SecurityPolicy] = []
        for pol in self._policies.values():
            if pol.enforcement_mode == PolicyEnforcementMode.DISABLED:
                continue
            if rule_id and pol.associated_rule_ids and rule_id not in pol.associated_rule_ids:
                continue
            if sink_category and pol.target_sink_categories and sink_category not in pol.target_sink_categories:
                continue
            if boundary_type and pol.source_boundaries and boundary_type not in pol.source_boundaries:
                continue
            applicable.append(pol)
        return applicable

    def detect_policy_conflicts(self, applicable_policies: list[SecurityPolicy]) -> list[str]:
        """Detect conflicting policy invariants (e.g. one mandates auth, another permits anonymous on same sink)."""
        conflicts = []
        if len(applicable_policies) > 1:
            req_auth = [p for p in applicable_policies if p.require_authentication]
            no_auth = [p for p in applicable_policies if not p.require_authentication]
            if req_auth and no_auth:
                conflicts.append(
                    f"Conflict between policies {[p.policy_id for p in req_auth]} (require auth) and {[p.policy_id for p in no_auth]} (anonymous permitted)"
                )
        return conflicts

    def evaluate_policy_outcome(
        self,
        policy: SecurityPolicy,
        property_state: SecurityPropertyState,
        auth_state: AuthenticationState = AuthenticationState.UNKNOWN,
        authz_state: AuthorizationState = AuthorizationState.UNKNOWN,
        sanitizer_id: Optional[str] = None,
        sink_category: Optional[SinkCategory] = None,
    ) -> PolicyEvaluationOutcome:
        """Evaluate policy returning rich PolicyEvaluationOutcome with proof obligations."""
        return policy.evaluate(
            sink_category=sink_category,
            property_state=property_state,
            auth_state=auth_state,
            authz_state=authz_state,
            sanitizer_id=sanitizer_id,
        )

    def evaluate_policy(
        self,
        policy: SecurityPolicy,
        property_state: SecurityPropertyState,
        auth_state: AuthenticationState = AuthenticationState.UNKNOWN,
        authz_state: AuthorizationState = AuthorizationState.UNKNOWN,
        sanitizer_id: Optional[str] = None,
        sink_category: Optional[SinkCategory] = None,
    ) -> tuple[PolicyEvaluationResult, list[str], list[str], str]:
        """Evaluate if the provided property state and context satisfies the policy.

        Returns:
            Tuple of (EvaluationResult, satisfied_properties, missing_properties, details)
        """
        outcome = self.evaluate_policy_outcome(
            policy=policy,
            property_state=property_state,
            auth_state=auth_state,
            authz_state=authz_state,
            sanitizer_id=sanitizer_id,
            sink_category=sink_category,
        )
        return (outcome.result, outcome.satisfied_properties, outcome.missing_properties, outcome.explanation)

    def _load_defaults(self) -> None:
        # POL-SQL-01: SQL query injection protection
        self.register_policy(
            SecurityPolicy(
                policy_id="POL-SQL-01",
                version=1,
                name="SQL Query Parameterization & Safety",
                description="Database queries accepting external data must use query parameterization or numeric type constraints.",
                source_boundaries=[
                    TrustBoundaryType.HTTP_REQUEST_PARAM,
                    TrustBoundaryType.HTTP_REQUEST_BODY,
                    TrustBoundaryType.DOM_INPUT,
                ],
                target_sink_categories=[SinkCategory.SQL_EXECUTE],
                required_security_properties=[SecurityProperty.SQL_SAFE],
                allowed_sanitizers=["int", "float", "integer", "Literal", "psycopg2.sql.Literal"],
                associated_rule_ids=["SEC-PY-005", "SEC-PY-009", "SEC-PY-011"],
                severity=FindingSeverity.HIGH,
            )
        )

        # POL-CMD-01: Command execution escaping
        self.register_policy(
            SecurityPolicy(
                policy_id="POL-CMD-01",
                version=1,
                name="OS Command Shell Escaping",
                description="Subprocess and OS command executions accepting external data must use shell quoting or argument vectors.",
                source_boundaries=[
                    TrustBoundaryType.HTTP_REQUEST_PARAM,
                    TrustBoundaryType.HTTP_REQUEST_BODY,
                    TrustBoundaryType.ENVIRONMENT_VARIABLE,
                ],
                target_sink_categories=[SinkCategory.COMMAND_EXECUTE],
                required_security_properties=[SecurityProperty.COMMAND_SAFE],
                allowed_sanitizers=["shlex.quote", "int", "float"],
                associated_rule_ids=["SEC-PY-003", "SEC-PY-010", "SEC-PY-012"],
                severity=FindingSeverity.HIGH,
            )
        )

        # POL-DOM-01: DOM injection and XSS prevention
        self.register_policy(
            SecurityPolicy(
                policy_id="POL-DOM-01",
                version=1,
                name="DOM and HTML Sanitization",
                description="DOM modifications and innerHTML assignments must use verified HTML sanitization.",
                source_boundaries=[
                    TrustBoundaryType.DOM_INPUT,
                    TrustBoundaryType.HTTP_REQUEST_PARAM,
                    TrustBoundaryType.HTTP_REQUEST_BODY,
                ],
                target_sink_categories=[SinkCategory.DOM_INJECTION],
                required_security_properties=[SecurityProperty.HTML_SAFE],
                allowed_sanitizers=["DOMPurify.sanitize", "sanitizeHtml", "int", "float"],
                associated_rule_ids=["SEC-JS-003", "SEC-JS-007", "SEC-JS-009"],
                severity=FindingSeverity.HIGH,
            )
        )

        # POL-EVAL-01: Dynamic code execution restriction
        self.register_policy(
            SecurityPolicy(
                policy_id="POL-EVAL-01",
                version=1,
                name="Restricted Dynamic Code Evaluation",
                description="Evaluations via eval() or Function() must not execute unvalidated external strings.",
                source_boundaries=[
                    TrustBoundaryType.HTTP_REQUEST_PARAM,
                    TrustBoundaryType.HTTP_REQUEST_BODY,
                    TrustBoundaryType.DOM_INPUT,
                ],
                target_sink_categories=[SinkCategory.CODE_EVAL],
                required_security_properties=[SecurityProperty.VALIDATED_TYPE],
                allowed_sanitizers=["int", "float"],
                associated_rule_ids=["SEC-PY-004", "SEC-JS-001", "SEC-JS-008", "SEC-JS-010"],
                severity=FindingSeverity.HIGH,
            )
        )

        # POL-AUTHZ-01: Privileged mutation authorization
        self.register_policy(
            SecurityPolicy(
                policy_id="POL-AUTHZ-01",
                version=1,
                name="Privileged Operation Authorization",
                description="Privileged administrative operations require verified authorization checks.",
                require_authentication=True,
                require_authorization=True,
                associated_rule_ids=["SEC-PY-008"],
                severity=FindingSeverity.MEDIUM,
            )
        )
