"""Regulatory control catalogs for PCI-DSS v4.0, HIPAA, SOC 2, and NIST SP 800-53 (Phase 26)."""

from typing import Optional
from analyzer.compliance.models import ComplianceControl, ComplianceFramework
from analyzer.models.findings import FindingSeverity
from analyzer.models.obligation import ObligationKind

# ============================================================================
# PCI-DSS v4.0 Control Catalog
# ============================================================================
PCI_DSS_V4_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="PCI-6.2.4",
        framework=ComplianceFramework.PCI_DSS_V4_0,
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
    ),
    ComplianceControl(
        control_id="PCI-3.4",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        name="Render Primary Account Number (PAN) Unreadable",
        section="Requirement 3: Protect Stored Account Data",
        description="Cardholder data and credentials must be rendered unreadable wherever stored, prohibiting hardcoded secrets and insecure cryptographic hashing.",
        mapped_rule_ids=["SEC-PY-001", "SEC-PY-006", "SEC-JS-004", "SEC-JS-005"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Never hardcode API keys, passwords, or secret keys. Use secure algorithms (e.g., SHA-256/argon2) rather than MD5/SHA-1.",
    ),
    ComplianceControl(
        control_id="PCI-8.3.1",
        framework=ComplianceFramework.PCI_DSS_V4_0,
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
    ),
    ComplianceControl(
        control_id="PCI-6.3.2",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        name="Software Component Inventory and Architecture Hygiene",
        section="Requirement 6: Develop and Maintain Secure Systems and Software",
        description="Maintain an inventory of bespoke custom software components and third-party libraries, preventing unmaintained architectural anti-patterns and circular coupling.",
        mapped_rule_ids=["ARC-001", "ARC-002", "ARC-003", "ARC-004", "ARC-005", "ARC-006", "ARC-007", "ARC-008", "ARC-009"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.MEDIUM,
        guidance="Resolve circular package dependencies, eliminate dead/orphan exports, and maintain an accurate CycloneDX Software Bill of Materials (SBOM).",
    ),
    ComplianceControl(
        control_id="PCI-6.5.10",
        framework=ComplianceFramework.PCI_DSS_V4_0,
        name="Cross-Origin and Inter-Component Request Integrity",
        section="Requirement 6: Develop and Maintain Secure Systems and Software",
        description="Web applications must protect against cross-origin data exposure and unvalidated postMessage/redirect vectors.",
        mapped_rule_ids=["SEC-PY-007", "SEC-JS-002", "SEC-JS-006"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Do not configure wildcard Access-Control-Allow-Origin headers with credentials, and validate target origins in postMessage calls.",
    ),
]

# ============================================================================
# HIPAA Security Rule (45 CFR Part 164 Subpart C) Control Catalog
# ============================================================================
HIPAA_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="HIPAA-164.312(a)(1)",
        framework=ComplianceFramework.HIPAA_SECURITY,
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
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(c)(1)",
        framework=ComplianceFramework.HIPAA_SECURITY,
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
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(e)(1)",
        framework=ComplianceFramework.HIPAA_SECURITY,
        name="Transmission Security & Boundary Protection",
        section="45 CFR § 164.312(e)(1) - Technical Safeguards",
        description="Implement technical security measures to guard against unauthorized access to electronic protected health information transmitted across electronic communications networks.",
        mapped_rule_ids=["SEC-PY-007", "SEC-JS-006", "SEC-JS-002"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Restrict cross-origin sharing policies and ensure external links and message channels cannot leak tokens or patient data.",
    ),
    ComplianceControl(
        control_id="HIPAA-164.312(b)",
        framework=ComplianceFramework.HIPAA_SECURITY,
        name="Audit Controls & Record Examination",
        section="45 CFR § 164.312(b) - Technical Safeguards",
        description="Implement mechanisms to record and examine system activity, preventing unreviewed changes and tracking security findings.",
        mapped_rule_ids=["SEC-PY-002"],  # Production debug enabled exposes internal states
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Disable debug modes in production and utilize cryptographic audit attestations to record scan activities.",
    ),
]

# ============================================================================
# SOC 2 Trust Services Criteria (TSC 2017/2022) Control Catalog
# ============================================================================
SOC2_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="SOC2-CC6.1",
        framework=ComplianceFramework.SOC2_TSC,
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
    ),
    ComplianceControl(
        control_id="SOC2-CC6.6",
        framework=ComplianceFramework.SOC2_TSC,
        name="Boundary Protection Against Threats",
        section="Common Criteria 6.6 - Boundary Protection",
        description="The entity implements logical boundaries and safeguards against security threats from outside system boundaries including injection and unauthorized execution.",
        mapped_rule_ids=["SEC-PY-003", "SEC-PY-010", "SEC-PY-012", "SEC-JS-003", "SEC-JS-007", "SEC-JS-009"],
        mapped_policy_ids=["POL-CMD-01", "POL-DOM-01"],
        required_obligations=[ObligationKind.REQUIRES_PROPERTY, ObligationKind.REQUIRES_VALIDATION],
        criticality=FindingSeverity.CRITICAL,
        guidance="Safeguard trust boundaries against command injection and client-side DOM manipulation.",
    ),
    ComplianceControl(
        control_id="SOC2-CC6.8",
        framework=ComplianceFramework.SOC2_TSC,
        name="Prevention of Unauthorized Code Execution",
        section="Common Criteria 6.8 - Malicious Code Prevention",
        description="The entity implements controls to prevent or detect malicious code or unauthorized dynamic execution.",
        mapped_rule_ids=["SEC-PY-004", "SEC-JS-001", "SEC-JS-008", "SEC-JS-010"],
        mapped_policy_ids=["POL-EVAL-01"],
        required_obligations=[ObligationKind.REQUIRES_PROPERTY],
        criticality=FindingSeverity.HIGH,
        guidance="Avoid dynamic eval/exec and prevent object prototype pollution.",
    ),
    ComplianceControl(
        control_id="SOC2-CC7.1",
        framework=ComplianceFramework.SOC2_TSC,
        name="Vulnerability Management and Configuration Monitoring",
        section="Common Criteria 7.1 - System Operations",
        description="The entity monitors infrastructure and software for vulnerabilities and security misconfigurations.",
        mapped_rule_ids=["SEC-PY-002", "SEC-PY-006", "SEC-JS-005"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.MEDIUM,
        guidance="Disable debug flags in production and eliminate deprecated weak hash algorithms.",
    ),
]

# ============================================================================
# NIST SP 800-53 Rev 5 Control Catalog
# ============================================================================
NIST_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="NIST-SI-10",
        framework=ComplianceFramework.NIST_SP_800_53_R5,
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
    ),
    ComplianceControl(
        control_id="NIST-AC-3",
        framework=ComplianceFramework.NIST_SP_800_53_R5,
        name="Access Enforcement",
        section="AC - Access Control",
        description="The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
        mapped_rule_ids=["SEC-PY-008"],
        mapped_policy_ids=["POL-AUTHZ-01"],
        required_obligations=[ObligationKind.REQUIRES_AUTHENTICATION, ObligationKind.REQUIRES_AUTHORIZATION],
        criticality=FindingSeverity.HIGH,
        guidance="Enforce access control policies on all sensitive functions and operations.",
    ),
    ComplianceControl(
        control_id="NIST-SC-13",
        framework=ComplianceFramework.NIST_SP_800_53_R5,
        name="Cryptographic Protection",
        section="SC - System and Communications Protection",
        description="The information system implements cryptographic mechanisms to prevent unauthorized disclosure and modification of sensitive information.",
        mapped_rule_ids=["SEC-PY-001", "SEC-PY-006", "SEC-JS-004", "SEC-JS-005"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.HIGH,
        guidance="Ensure only approved cryptographic algorithms are utilized and secrets are managed outside source code.",
    ),
    ComplianceControl(
        control_id="NIST-SC-8",
        framework=ComplianceFramework.NIST_SP_800_53_R5,
        name="Transmission Confidentiality and Integrity",
        section="SC - System and Communications Protection",
        description="The information system protects the confidentiality and integrity of transmitted information against unauthorized eavesdropping and injection.",
        mapped_rule_ids=["SEC-PY-007", "SEC-JS-006"],
        mapped_policy_ids=[],
        required_obligations=[],
        criticality=FindingSeverity.MEDIUM,
        guidance="Ensure appropriate CORS headers and secure messaging boundaries are enforced.",
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
