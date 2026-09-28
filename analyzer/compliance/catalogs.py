"""Regulatory control catalogs for PCI-DSS v4.0, HIPAA, SOC 2, and NIST SP 800-53 (Phase 26/27)."""

from typing import Optional
from analyzer.compliance.models import (
    ComplianceControl,
    ComplianceFramework,
    ControlProvenance,
    MappingType,
)
from analyzer.models.findings import FindingSeverity
from analyzer.models.obligation import ObligationKind

# ============================================================================
# PCI-DSS v4.0 Control Catalog
# ============================================================================
PCI_DSS_V4_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="PCI-6.2.4",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        framework_version="v4.0",
        name="Software Vulnerability Mitigation",
        section="Requirement 6: Develop and Maintain Secure Systems and Software",
        description="Bespoke and custom software is developed securely to prevent common software vulnerabilities including injection attacks, OS command injection, and cross-site scripting.",
        mapped_rule_ids=[
            "SEC-PY-003", "SEC-PY-005", "SEC-PY-009", "SEC-PY-010", "SEC-PY-011", "SEC-PY-012",
            "SEC-JS-001", "SEC-JS-003", "SEC-JS-007", "SEC-JS-008", "SEC-JS-009", "SEC-JS-010",
        ],
        mapped_policy_ids=["POL-SQL-01", "POL-CMD-01", "POL-DOM-01", "POL-EVAL-01"],
        required_obligations=[
            ObligationKind.REQUIRES_PROPERTY,
            ObligationKind.REQUIRES_PARAMETERIZATION,
            ObligationKind.REQUIRES_VALIDATION,
        ],
        criticality=FindingSeverity.CRITICAL,
        guidance="Employ query parameterization for SQL queries, argument lists without shell=True for OS commands, and HTML sanitization for DOM outputs.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot verify third-party binary dependencies without source code",
            "Does not assess web application firewall (WAF) runtime effectiveness",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="PCI-DSS v4.0",
            official_reference="Requirement 6.2.4, Page 58",
            requirement_summary="Prevent common vulnerabilities in bespoke software",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="AST & Taint analysis for SQL, Command, DOM, and Eval injection vulnerabilities",
            static_limitations=[
                "Cannot verify third-party binary dependencies without source code",
                "Does not assess web application firewall (WAF) runtime effectiveness",
            ],
            auditor_notes="Static technical evidence only; does not replace ASV vulnerability scanning",
        ),
    ),
    ComplianceControl(
        control_id="PCI-3.4",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        framework_version="v4.0",
        name="Render Primary Account Number (PAN) Unreadable",
        section="Requirement 3: Protect Stored Account Data",
        description="Cardholder data and credentials must be rendered unreadable wherever stored, prohibiting hardcoded secrets and insecure cryptographic hashing.",
        mapped_rule_ids=["SEC-PY-001", "SEC-PY-006", "SEC-JS-004", "SEC-JS-005"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Never hardcode API keys, passwords, or secret keys. Use secure algorithms (e.g., SHA-256/argon2) rather than MD5/SHA-1.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot verify hardware security modules (HSM) or database volume encryption at rest",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="PCI-DSS v4.0",
            official_reference="Requirement 3.4, Page 35",
            requirement_summary="Protect stored account data and credentials",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Static detection of hardcoded secrets, private keys, and weak hashes (MD5, SHA-1)",
            static_limitations=[
                "Cannot verify hardware security modules (HSM) or database volume encryption at rest",
            ],
            auditor_notes="Verifies source-level absence of plaintext secrets; does not assess KMS infrastructure",
        ),
    ),
    ComplianceControl(
        control_id="PCI-8.3.1",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        framework_version="v4.0",
        name="Strong Authentication and Access Enforcement",
        section="Requirement 8: Identify Users and Authenticate Access to System Components",
        description="Multi-factor or strong authentication and authorization must be enforced on privileged system functions and APIs.",
        mapped_rule_ids=["SEC-PY-008"],
        mapped_policy_ids=["POL-AUTHZ-01"],
        required_obligations=[
            ObligationKind.REQUIRES_AUTHENTICATION,
            ObligationKind.REQUIRES_AUTHORIZATION,
        ],
        criticality=FindingSeverity.HIGH,
        guidance="Ensure all non-public mutation endpoints require authentication decorators or middleware, and avoid bypassing CSRF validation.",
        mapping_type=MappingType.PARTIAL,
        static_limitations=[
            "Cannot verify MFA hardware tokens, biometric auth, or password rotation policies",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="PCI-DSS v4.0",
            official_reference="Requirement 8.3.1, Page 72",
            requirement_summary="Strong authentication and access enforcement on APIs",
            mapping_type=MappingType.PARTIAL,
            static_analysis_scope="Interprocedural authorization decorator and middleware verification",
            static_limitations=[
                "Cannot verify MFA hardware tokens, biometric auth, or password rotation policies",
            ],
            auditor_notes="Validates route-level decorator enforcement only",
        ),
    ),
    ComplianceControl(
        control_id="PCI-6.3.2",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        framework_version="v4.0",
        name="Software Component Inventory and Architecture Hygiene",
        section="Requirement 6: Develop and Maintain Secure Systems and Software",
        description="Maintain an inventory of bespoke custom software components and third-party libraries, preventing unmaintained architectural anti-patterns and circular coupling.",
        mapped_rule_ids=["ARC-001", "ARC-002", "ARC-003", "ARC-004", "ARC-005", "ARC-006", "ARC-007", "ARC-008", "ARC-009"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.MEDIUM,
        guidance="Resolve circular package dependencies, eliminate dead/orphan exports, and maintain an accurate CycloneDX Software Bill of Materials (SBOM).",
        mapping_type=MappingType.SUPPORTING,
        static_limitations=[
            "Does not verify commercial software licensing agreements or vendor contracts",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="PCI-DSS v4.0",
            official_reference="Requirement 6.3.2, Page 61",
            requirement_summary="Inventory of bespoke software components and libraries",
            mapping_type=MappingType.SUPPORTING,
            static_analysis_scope="Package dependency coupling, circular dependencies, and CycloneDX SBOM component enumeration",
            static_limitations=[
                "Does not verify commercial software licensing agreements or vendor contracts",
            ],
            auditor_notes="Structural module coupling and component graph verification",
        ),
    ),
    ComplianceControl(
        control_id="PCI-6.5.10",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        framework_version="v4.0",
        name="Cross-Origin and Inter-Component Request Integrity",
        section="Requirement 6: Develop and Maintain Secure Systems and Software",
        description="Web applications must protect against cross-origin data exposure and unvalidated postMessage/redirect vectors.",
        mapped_rule_ids=["SEC-PY-007", "SEC-JS-002", "SEC-JS-006"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Do not configure wildcard Access-Control-Allow-Origin headers with credentials, and validate target origins in postMessage calls.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot verify reverse-proxy or CDN CORS header rewriting rules",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="PCI-DSS v4.0",
            official_reference="Requirement 6.5.10, Page 64",
            requirement_summary="Cross-origin security and communication integrity",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="CORS wildcard credentials and unvalidated postMessage targets",
            static_limitations=[
                "Cannot verify reverse-proxy or CDN CORS header rewriting rules",
            ],
            auditor_notes="Evaluates application source code CORS configurations",
        ),
    ),
]

# ============================================================================
# HIPAA Security Rule (45 CFR Part 164 Subpart C) Control Catalog
# ============================================================================
HIPAA_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="HIPAA-164.312(a)(1)",
        framework=ComplianceFramework.HIPAA_SECURITY,
        framework_version="45 CFR Part 164 Subpart C",
        name="Access Control (Unique User Identification)",
        section="45 CFR § 164.312(a)(1) - Technical Safeguards",
        description="Implement technical policies and procedures for electronic information systems maintaining electronic protected health information (ePHI) to allow access only to authorized individuals.",
        mapped_rule_ids=["SEC-PY-008"],
        mapped_policy_ids=["POL-AUTHZ-01"],
        required_obligations=[
            ObligationKind.REQUIRES_AUTHENTICATION,
            ObligationKind.REQUIRES_AUTHORIZATION,
        ],
        criticality=FindingSeverity.HIGH,
        guidance="Require verified identity and permission enforcement on endpoints accessing or modifying patient records.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Does not verify identity provider (IdP) directory integrations or physical terminal access",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="HIPAA Security Rule",
            official_reference="45 CFR § 164.312(a)(1)",
            requirement_summary="Access control to electronic protected health information (ePHI)",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Endpoint authentication and authorization enforcement checks",
            static_limitations=[
                "Does not verify identity provider (IdP) directory integrations or physical terminal access",
            ],
            auditor_notes="Technical safeguard assessment only; administrative safeguards unassessed",
        ),
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(c)(1)",
        framework=ComplianceFramework.HIPAA_SECURITY,
        framework_version="45 CFR Part 164 Subpart C",
        name="Data Integrity Verification",
        section="45 CFR § 164.312(c)(1) - Technical Safeguards",
        description="Implement policies and procedures to protect electronic protected health information from improper alteration or destruction via injection or unsafe data manipulation.",
        mapped_rule_ids=["SEC-PY-005", "SEC-PY-009", "SEC-PY-011"],
        mapped_policy_ids=["POL-SQL-01"],
        required_obligations=[
            ObligationKind.REQUIRES_PROPERTY,
            ObligationKind.REQUIRES_PARAMETERIZATION,
        ],
        criticality=FindingSeverity.CRITICAL,
        guidance="Use parameterized queries and strong typing to safeguard database integrity and patient records.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot verify database disk corruption or hardware-level write protection",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="HIPAA Security Rule",
            official_reference="45 CFR § 164.312(c)(1)",
            requirement_summary="Protection of ePHI from improper alteration or destruction",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="SQL injection, ORM parameterization, and data mutation integrity",
            static_limitations=[
                "Cannot verify database disk corruption or hardware-level write protection",
            ],
            auditor_notes="Verifies application-level protection against unauthorized data tampering",
        ),
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(e)(1)",
        framework=ComplianceFramework.HIPAA_SECURITY,
        framework_version="45 CFR Part 164 Subpart C",
        name="Transmission Security & Boundary Protection",
        section="45 CFR § 164.312(e)(1) - Technical Safeguards",
        description="Implement technical security measures to guard against unauthorized access to electronic protected health information transmitted across electronic communications networks.",
        mapped_rule_ids=["SEC-PY-007", "SEC-JS-006", "SEC-JS-002"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Restrict cross-origin sharing policies and ensure external links and message channels cannot leak tokens or patient data.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot inspect TLS certificate validation or network cipher suites on wire",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="HIPAA Security Rule",
            official_reference="45 CFR § 164.312(e)(1)",
            requirement_summary="Guarding ePHI transmitted across communications networks",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Application transmission boundaries, CORS policies, and token leakage",
            static_limitations=[
                "Cannot inspect TLS certificate validation or network cipher suites on wire",
            ],
            auditor_notes="Assesses application security boundaries; TLS network audit required separately",
        ),
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(b)",
        framework=ComplianceFramework.HIPAA_SECURITY,
        framework_version="45 CFR Part 164 Subpart C",
        name="Audit Controls & Record Examination",
        section="45 CFR § 164.312(b) - Technical Safeguards",
        description="Implement mechanisms to record and examine system activity, preventing unreviewed changes and tracking security findings.",
        mapped_rule_ids=["SEC-PY-002"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Disable debug modes in production and utilize cryptographic audit attestations to record scan activities.",
        mapping_type=MappingType.SUPPORTING,
        static_limitations=[
            "Cannot verify SIEM log retention or operational log monitoring practices",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="HIPAA Security Rule",
            official_reference="45 CFR § 164.312(b)",
            requirement_summary="Audit controls to record and examine activity in systems containing ePHI",
            mapping_type=MappingType.SUPPORTING,
            static_analysis_scope="Detection of insecure debug modes and emission of tamper-evident audit trails",
            static_limitations=[
                "Cannot verify SIEM log retention or operational log monitoring practices",
            ],
            auditor_notes="Supporting technical evidence of secure operational configuration",
        ),
    ),
]

# ============================================================================
# SOC 2 Trust Services Criteria (TSC 2017/2022) Control Catalog
# ============================================================================
SOC2_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="SOC2-CC6.1",
        framework=ComplianceFramework.SOC2_TSC,
        framework_version="2017/2022 TSC",
        name="Logical Access Controls",
        section="Common Criteria 6.1 - Logical and Physical Access",
        description="The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
        mapped_rule_ids=["SEC-PY-001", "SEC-PY-008", "SEC-JS-004"],
        mapped_policy_ids=["POL-AUTHZ-01"],
        required_obligations=[
            ObligationKind.REQUIRES_AUTHENTICATION,
            ObligationKind.REQUIRES_AUTHORIZATION,
        ],
        criticality=FindingSeverity.HIGH,
        guidance="Eliminate hardcoded secrets and enforce role-based access checks on sensitive actions.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot evaluate employee onboarding/offboarding access revocation procedures",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="SOC 2 Trust Services Criteria",
            official_reference="CC6.1",
            requirement_summary="Implementation of logical access controls to protect information assets",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Prohibition of hardcoded credentials and verification of authorization decorators",
            static_limitations=[
                "Cannot evaluate employee onboarding/offboarding access revocation procedures",
            ],
            auditor_notes="Technical evidence only; does not replace auditor review of user access reviews",
        ),
    ),
    ComplianceControl(
        control_id="SOC2-CC6.6",
        framework=ComplianceFramework.SOC2_TSC,
        framework_version="2017/2022 TSC",
        name="Boundary Protection Against Threats",
        section="Common Criteria 6.6 - Boundary Protection",
        description="The entity implements logical boundaries and safeguards against security threats from outside system boundaries including injection and unauthorized execution.",
        mapped_rule_ids=["SEC-PY-003", "SEC-PY-010", "SEC-PY-012", "SEC-JS-003", "SEC-JS-007", "SEC-JS-009"],
        mapped_policy_ids=["POL-CMD-01", "POL-DOM-01"],
        required_obligations=[ObligationKind.REQUIRES_PROPERTY, ObligationKind.REQUIRES_VALIDATION],
        criticality=FindingSeverity.CRITICAL,
        guidance="Safeguard trust boundaries against command injection and client-side DOM manipulation.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot assess network firewall rules, VPC configurations, or cloud security groups",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="SOC 2 Trust Services Criteria",
            official_reference="CC6.6",
            requirement_summary="Logical boundaries and safeguards against security threats",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Software boundary validation, sanitization of inputs, and command isolation",
            static_limitations=[
                "Cannot assess network firewall rules, VPC configurations, or cloud security groups",
            ],
            auditor_notes="Evaluates application boundary enforcement",
        ),
    ),
    ComplianceControl(
        control_id="SOC2-CC6.8",
        framework=ComplianceFramework.SOC2_TSC,
        framework_version="2017/2022 TSC",
        name="Prevention of Unauthorized Code Execution",
        section="Common Criteria 6.8 - Malicious Code Prevention",
        description="The entity implements controls to prevent or detect malicious code or unauthorized dynamic execution.",
        mapped_rule_ids=["SEC-PY-004", "SEC-JS-001", "SEC-JS-008", "SEC-JS-010"],
        mapped_policy_ids=["POL-EVAL-01"],
        required_obligations=[ObligationKind.REQUIRES_PROPERTY],
        criticality=FindingSeverity.HIGH,
        guidance="Avoid dynamic eval/exec and prevent object prototype pollution.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot verify host antivirus or endpoint detection and response (EDR) runtime agents",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="SOC 2 Trust Services Criteria",
            official_reference="CC6.8",
            requirement_summary="Controls to prevent or detect unauthorized mobile code or execution",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Prohibition of dynamic code evaluation, deserialization vulnerabilities, and prototype pollution",
            static_limitations=[
                "Cannot verify host antivirus or endpoint detection and response (EDR) runtime agents",
            ],
            auditor_notes="Validates prevention of dynamic execution vectors in application code",
        ),
    ),
    ComplianceControl(
        control_id="SOC2-CC7.1",
        framework=ComplianceFramework.SOC2_TSC,
        framework_version="2017/2022 TSC",
        name="Vulnerability Management and Configuration Monitoring",
        section="Common Criteria 7.1 - System Operations",
        description="The entity monitors infrastructure and software for vulnerabilities and security misconfigurations.",
        mapped_rule_ids=["SEC-PY-002", "SEC-PY-006", "SEC-JS-005"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.MEDIUM,
        guidance="Disable debug flags in production and eliminate deprecated weak hash algorithms.",
        mapping_type=MappingType.SUPPORTING,
        static_limitations=[
            "Does not verify third-party penetration testing reports or external bug bounty triage",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="SOC 2 Trust Services Criteria",
            official_reference="CC7.1",
            requirement_summary="Vulnerability monitoring and configuration management",
            mapping_type=MappingType.SUPPORTING,
            static_analysis_scope="Static scanning of configuration flags and cryptographic algorithm choices",
            static_limitations=[
                "Does not verify third-party penetration testing reports or external bug bounty triage",
            ],
            auditor_notes="Provides evidence of automated vulnerability scanning in SDLC",
        ),
    ),
]

# ============================================================================
# NIST SP 800-53 Rev 5 Control Catalog
# ============================================================================
NIST_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="NIST-SI-10",
        framework=ComplianceFramework.NIST_SP_800_53_R5,
        framework_version="Rev 5",
        name="Information Input Validation",
        section="SI - System and Information Integrity",
        description="The information system checks information for accuracy, completeness, and validity before processing, preventing injection flaws.",
        mapped_rule_ids=[
            "SEC-PY-003", "SEC-PY-005", "SEC-PY-009", "SEC-PY-010", "SEC-PY-011", "SEC-PY-012",
            "SEC-JS-003", "SEC-JS-007", "SEC-JS-009",
        ],
        mapped_policy_ids=["POL-SQL-01", "POL-CMD-01", "POL-DOM-01"],
        required_obligations=[ObligationKind.REQUIRES_PROPERTY, ObligationKind.REQUIRES_VALIDATION],
        criticality=FindingSeverity.CRITICAL,
        guidance="Validate all inputs against formal specifications and enforce parameterization at sinks.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot assess manual business-logic input validation performed outside codebase",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="NIST SP 800-53 Rev 5",
            official_reference="Control SI-10",
            requirement_summary="Input validation rules and syntax checks",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Taint analysis from untrusted HTTP/JSON sources to sensitive sinks",
            static_limitations=[
                "Cannot assess manual business-logic input validation performed outside codebase",
            ],
            auditor_notes="Verifies technical input validation at software boundary",
        ),
    ),
    ComplianceControl(
        control_id="NIST-AC-3",
        framework=ComplianceFramework.NIST_SP_800_53_R5,
        framework_version="Rev 5",
        name="Access Enforcement",
        section="AC - Access Control",
        description="The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
        mapped_rule_ids=["SEC-PY-008"],
        mapped_policy_ids=["POL-AUTHZ-01"],
        required_obligations=[ObligationKind.REQUIRES_AUTHENTICATION, ObligationKind.REQUIRES_AUTHORIZATION],
        criticality=FindingSeverity.HIGH,
        guidance="Enforce access control policies on all sensitive functions and operations.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot verify RBAC role assignment changes in external database/directory",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="NIST SP 800-53 Rev 5",
            official_reference="Control AC-3",
            requirement_summary="Access enforcement at system boundaries",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Authorization decorators, permission verification, and policy enforcement",
            static_limitations=[
                "Cannot verify RBAC role assignment changes in external database/directory",
            ],
            auditor_notes="Validates code-level access enforcement mechanisms",
        ),
    ),
    ComplianceControl(
        control_id="NIST-SC-13",
        framework=ComplianceFramework.NIST_SP_800_53_R5,
        framework_version="Rev 5",
        name="Cryptographic Protection",
        section="SC - System and Communications Protection",
        description="The information system implements cryptographic mechanisms to prevent unauthorized disclosure and modification of sensitive information.",
        mapped_rule_ids=["SEC-PY-001", "SEC-PY-006", "SEC-JS-004", "SEC-JS-005"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Ensure only approved cryptographic algorithms are utilized and secrets are managed outside source code.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot verify FIPS 140-2/3 cryptographic module certification of underlying OS libraries",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="NIST SP 800-53 Rev 5",
            official_reference="Control SC-13",
            requirement_summary="Cryptographic protection of sensitive data",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Prohibition of weak hashing algorithms (MD5, SHA-1) and hardcoded private keys",
            static_limitations=[
                "Cannot verify FIPS 140-2/3 cryptographic module certification of underlying OS libraries",
            ],
            auditor_notes="Evaluates algorithmic strength and secret hygiene in source code",
        ),
    ),
    ComplianceControl(
        control_id="NIST-SC-8",
        framework=ComplianceFramework.NIST_SP_800_53_R5,
        framework_version="Rev 5",
        name="Transmission Confidentiality and Integrity",
        section="SC - System and Communications Protection",
        description="The information system protects the confidentiality and integrity of transmitted information against unauthorized eavesdropping and injection.",
        mapped_rule_ids=["SEC-PY-007", "SEC-JS-006"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.MEDIUM,
        guidance="Ensure appropriate CORS headers and secure messaging boundaries are enforced.",
        mapping_type=MappingType.DIRECT,
        static_limitations=[
            "Cannot verify TLS version negotiation or cipher suite configurations on external load balancers",
        ],
        provenance=ControlProvenance(
            catalog_version="2026.1",
            source_standard="NIST SP 800-53 Rev 5",
            official_reference="Control SC-8",
            requirement_summary="Protection of transmitted information against eavesdropping and modification",
            mapping_type=MappingType.DIRECT,
            static_analysis_scope="Application-level communication boundary and cross-origin security headers",
            static_limitations=[
                "Cannot verify TLS version negotiation or cipher suite configurations on external load balancers",
            ],
            auditor_notes="Technical assessment of application cross-origin security",
        ),
    ),
]

# Master Catalog Mapping
ALL_COMPLIANCE_CONTROLS: dict[ComplianceFramework, list[ComplianceControl]] = {
    ComplianceFramework.PCI_DSS_V4_0: PCI_DSS_V4_CONTROLS,
    ComplianceFramework.HIPAA_SECURITY: HIPAA_CONTROLS,
    ComplianceFramework.SOC2_TSC: SOC2_CONTROLS,
    ComplianceFramework.NIST_SP_800_53_R5: NIST_CONTROLS,
}


def get_controls_for_framework(framework: ComplianceFramework) -> list[ComplianceControl]:
    """Retrieve all compliance controls for a specific framework."""
    return ALL_COMPLIANCE_CONTROLS.get(framework, [])


def find_control_by_id(control_id: str) -> Optional[ComplianceControl]:
    """Find a control across all frameworks by its unique identifier."""
    norm_id = control_id.strip().upper()
    for controls in ALL_COMPLIANCE_CONTROLS.values():
        for c in controls:
            if c.control_id.upper() == norm_id:
                return c
    return None
