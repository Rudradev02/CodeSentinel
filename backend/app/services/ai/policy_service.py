"""Natural-language security policy translation and lifecycle management service for Phase 30.

Translates high-level natural language security requirements into strongly-typed
SecurityPolicy candidate definitions, validates them deterministically against
CodeSentinel's semantic domains, and manages human approval gates.
"""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Optional
from sqlalchemy.orm import Session

from analyzer.rules.policy import PolicyEnforcementMode, SecurityPolicy, SecurityPolicyRegistry
from analyzer.rules.policy_authoring import (
    PolicyValidationStatus,
    SecurityPolicyCandidateDTO,
    SemanticPolicyValidator,
    STANDARD_KNOWN_SANITIZERS,
)
from backend.app.models.triage_feedback import AIPolicyProposalRecord
from backend.app.services.ai.orchestrator import AIEnrichmentOrchestrator
from backend.app.services.ai.providers.base import BaseLLMProvider
from backend.app.services.ai.scrubber import SecretScrubber

logger = logging.getLogger(__name__)

POLICY_SYSTEM_PROMPT = """You are CodeSentinel Policy Compiler, a specialized security compiler that converts natural language security rules into strict, declarative SecurityPolicyCandidate JSON schemas.

CRITICAL COMPILER INSTRUCTIONS:
1. Output ONLY a valid JSON object matching the requested schema. No conversational text, markdown formatting, or preamble.
2. Sinks MUST be one or more valid SinkCategory values:
   ["SQL_EXECUTE", "COMMAND_INJECTION", "CODE_EXECUTION", "PATH_TRAVERSAL", "XSS", "SSRF", "LOG_INJECTION", "DESERIALIZATION", "CRYPTO_OPERATION", "FILE_WRITE", "FILE_READ"]
3. Source boundaries MUST be zero or more valid TrustBoundaryType values:
   ["HTTP_REQUEST_PARAM", "HTTP_REQUEST_BODY", "DOM_INPUT", "ENVIRONMENT_VARIABLE", "FILE_SYSTEM", "DATABASE_RECORD", "INTERNAL_SERVICE", "PUBLIC_INTERNET_UNAUTHENTICATED"]
4. Required security properties MUST be zero or more valid SecurityProperty values:
   ["SQL_PARAMETRIZED", "SHELL_ESCAPED", "HTML_ESCAPED", "URL_ENCODED", "PATH_CANONICALIZED", "TYPE_COERCED_INT", "TYPE_COERCED_FLOAT"]
5. Allowed sanitizers MUST be selected from registered standard sanitizers:
   ["int", "float", "shlex.quote", "html.escape", "psycopg2.sql.Literal", "quote", "DOMPurify.sanitize", "sanitizeHtml", "escape", "encodeURIComponent", "strconv.Atoi", "strconv.ParseInt", "html.EscapeString", "url.QueryEscape"]
6. Enforcement mode MUST be "ENFORCE" or "ADVISORY".
7. Policy ID must start with "POL-" and contain only uppercase letters, numbers, and hyphens (e.g. POL-SQL-01).
8. If the directive is vague (e.g. "make code secure", "prevent hacking"), do NOT guess arbitrarily; omit required properties so validation safely catches ambiguity.
"""

POLICY_JSON_SCHEMA_EXAMPLE = """{
  "policy_id": "POL-SQL-01",
  "name": "SQL Query Parameterization Policy",
  "description": "Requires all SQL execution operations from HTTP parameters to be parameterized or sanitized.",
  "source_boundaries": ["HTTP_REQUEST_PARAM", "HTTP_REQUEST_BODY"],
  "target_sink_categories": ["SQL_EXECUTE"],
  "required_security_properties": ["SQL_PARAMETRIZED"],
  "allowed_sanitizers": ["int", "psycopg2.sql.Literal", "strconv.Atoi"],
  "require_authentication": true,
  "require_authorization": false,
  "enforcement_mode": "ENFORCE",
  "associated_rule_ids": ["SEC-PY-005", "SEC-JS-001", "SEC-GO-002"],
  "severity": "HIGH"
}"""


class NaturalLanguagePolicyService:
    """Service for natural-language policy translation, validation, and lifecycle management."""

    @classmethod
    def build_translation_prompt(cls, natural_language_input: str) -> str:
        """Build grammar-constrained translation prompt for the LLM."""
        scrubbed_input = SecretScrubber.scrub(natural_language_input)
        return (
            f"Convert the following natural-language security requirement into a declarative SecurityPolicyCandidate JSON object:\n\n"
            f"<requirement>\n{scrubbed_input}\n</requirement>\n\n"
            f"Schema example:\n{POLICY_JSON_SCHEMA_EXAMPLE}\n"
        )

    @classmethod
    def translate_prompt_to_candidate(
        cls,
        natural_language_input: str,
        provider: Optional[BaseLLMProvider] = None,
        model_name: Optional[str] = None,
    ) -> tuple[PolicyValidationStatus, Optional[dict[str, Any]], list[str]]:
        """Translate natural-language requirement into candidate JSON via LLM provider.

        If provider is None, attempts to use configured provider from AIEnrichmentOrchestrator.
        """
        # Pre-check for empty or overtly vague directives without wasting LLM tokens
        vague_re = re.compile(r"^\s*(make (this )?(code|app|software) (secure|safe)|prevent all hacking|stop hackers|be safe)\s*$", re.IGNORECASE)
        if vague_re.match(natural_language_input.strip()):
            return (
                PolicyValidationStatus.UNKNOWN_OR_AMBIGUOUS,
                None,
                ["REJECTION: Vague security goal cannot be mapped to deterministic SecurityProperty or SinkCategory."],
            )

        if provider is None:
            try:
                provider, _, model_name = AIEnrichmentOrchestrator.get_provider(model_name=model_name)
            except Exception as e:
                logger.warning("Could not instantiate AI provider for policy translation: %s. Falling back to deterministic compiler.", e)
                return cls._deterministic_fallback_translation(natural_language_input, error_reason=str(e))

        user_prompt = cls.build_translation_prompt(natural_language_input)

        try:
            response = provider.generate_sync(
                prompt=user_prompt,
                system_prompt=POLICY_SYSTEM_PROMPT,
                model=model_name,
                temperature=0.1,  # Low temperature for strict declarative compliance
            )
            if response.parsed_json is not None:
                candidate_json = response.parsed_json
            else:
                raw_text = response.raw_content.strip()

                # Clean markdown codeblocks if model wrapped output in ```json ... ```
                if raw_text.startswith("```"):
                    lines = raw_text.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    raw_text = "\n".join(lines).strip()

                candidate_json = json.loads(raw_text)
        except Exception as exc:
            logger.warning("Failed to generate or parse candidate JSON from LLM: %s. Activating deterministic grammar compiler fallback.", exc)
            return cls._deterministic_fallback_translation(natural_language_input, error_reason=str(exc))

        status, _, diagnostics = SemanticPolicyValidator.validate(candidate_json, raw_prompt=natural_language_input)
        return status, candidate_json, diagnostics

    @classmethod
    def _deterministic_fallback_translation(
        cls,
        natural_language_input: str,
        error_reason: str = "",
    ) -> tuple[PolicyValidationStatus, Optional[dict[str, Any]], list[str]]:
        """Deterministic grammar compiler fallback for Quick Policy Templates and standard security requirements.

        Invoked when LLM provider is offline, unauthorized (401), or times out.
        """
        raw_text = natural_language_input.strip()
        lower = raw_text.lower()

        candidate_dict: Optional[dict[str, Any]] = None

        if "sql" in lower or "database" in lower or "query" in lower:
            req_props = ["SQL_PARAMETRIZED"]
            if "int" in lower or "integer" in lower or "cast" in lower:
                req_props.append("TYPE_COERCED_INT")
            candidate_dict = {
                "policy_id": "POL-SQL-PARAM",
                "name": "SQL Query Parameterization Policy",
                "description": "Requires all SQL execution operations from HTTP parameters to be parameterized or cast to integer.",
                "source_boundaries": ["HTTP_REQUEST_PARAM", "HTTP_REQUEST_BODY"],
                "target_sink_categories": ["SQL_EXECUTE"],
                "required_security_properties": req_props,
                "allowed_sanitizers": ["int", "psycopg2.sql.Literal", "strconv.Atoi"],
                "require_authentication": True if ("auth" in lower and "unauth" not in lower) else False,
                "require_authorization": False,
                "enforcement_mode": "ENFORCE",
                "associated_rule_ids": ["SEC-PY-005", "SEC-JS-001", "SEC-GO-002"],
                "severity": "HIGH",
            }
        elif "command" in lower or "shell" in lower or "cli" in lower or "process" in lower or "subprocess" in lower:
            candidate_dict = {
                "policy_id": "POL-CMD-DEFENSE",
                "name": "Command Execution Defense Policy",
                "description": "Disallow unauthenticated shell execution and require shell escaping on all process sinks.",
                "source_boundaries": ["HTTP_REQUEST_PARAM", "CLI_ARGUMENT", "ENVIRONMENT_VARIABLE"],
                "target_sink_categories": ["COMMAND_EXECUTE"],
                "required_security_properties": ["SHELL_ESCAPED"],
                "allowed_sanitizers": ["shlex.quote"],
                "require_authentication": True,
                "require_authorization": False,
                "enforcement_mode": "ENFORCE",
                "associated_rule_ids": ["SEC-PY-001", "SEC-JS-002", "SEC-GO-001"],
                "severity": "CRITICAL",
            }
        elif "xss" in lower or "dom" in lower or "dompurify" in lower or "html" in lower or "sanitize" in lower:
            candidate_dict = {
                "policy_id": "POL-DOM-XSS",
                "name": "DOM XSS Sanitization Policy",
                "description": "Require DOMPurify.sanitize or HTML escaping before rendering untrusted inputs into DOM injection sinks.",
                "source_boundaries": ["DOM_INPUT", "HTTP_REQUEST_PARAM"],
                "target_sink_categories": ["DOM_INJECTION"],
                "required_security_properties": ["HTML_ESCAPED"],
                "allowed_sanitizers": ["DOMPurify.sanitize", "html.escape", "html.EscapeString"],
                "require_authentication": False,
                "require_authorization": False,
                "enforcement_mode": "ENFORCE",
                "associated_rule_ids": ["SEC-JS-003", "SEC-JS-004"],
                "severity": "HIGH",
            }
        elif "path" in lower or "traversal" in lower or "file system" in lower or "file write" in lower or "file read" in lower or "file" in lower:
            candidate_dict = {
                "policy_id": "POL-PATH-TRAVERSAL",
                "name": "Path Traversal Guard Policy",
                "description": "Require path canonicalization and verification on all file system write operations from HTTP parameters.",
                "source_boundaries": ["HTTP_REQUEST_PARAM", "HTTP_REQUEST_BODY"],
                "target_sink_categories": ["FILE_PATH"],
                "required_security_properties": ["PATH_CANONICALIZED"],
                "allowed_sanitizers": [],
                "require_authentication": False,
                "require_authorization": False,
                "enforcement_mode": "ENFORCE",
                "associated_rule_ids": ["SEC-PY-002", "SEC-GO-003"],
                "severity": "HIGH",
            }
        elif "eval" in lower or "code execution" in lower or "code execute" in lower:
            candidate_dict = {
                "policy_id": "POL-EVAL-RESTRICT",
                "name": "Dynamic Code Execution Policy",
                "description": "Restricts dynamic code evaluation and string execution from untrusted boundaries.",
                "source_boundaries": ["HTTP_REQUEST_PARAM", "ENVIRONMENT_VARIABLE"],
                "target_sink_categories": ["CODE_EVAL"],
                "required_security_properties": ["COMMAND_SAFE"],
                "allowed_sanitizers": [],
                "require_authentication": True,
                "require_authorization": False,
                "enforcement_mode": "ENFORCE",
                "associated_rule_ids": ["SEC-PY-003", "SEC-JS-005"],
                "severity": "CRITICAL",
            }

        if not candidate_dict:
            return (
                PolicyValidationStatus.UNKNOWN_OR_AMBIGUOUS,
                None,
                [
                    f"LLM provider unavailable or unauthorized ({error_reason}).",
                    "Deterministic grammar compiler could not map input to a registered SinkCategory or SecurityProperty.",
                ],
            )

        status, _, diagnostics = SemanticPolicyValidator.validate(candidate_dict, raw_prompt=natural_language_input)
        if status == PolicyValidationStatus.VALIDATED_CANDIDATE:
            diagnostics.append(
                f"Deterministic compiler active: Synthesized and validated offline from grammar rules (LLM provider note: {error_reason or 'offline'})."
            )
        return status, candidate_dict, diagnostics

    @classmethod
    def author_policy(
        cls,
        natural_language_input: str,
        author_id: str,
        db: Optional[Session] = None,
        provider: Optional[BaseLLMProvider] = None,
        model_name: Optional[str] = None,
    ) -> tuple[PolicyValidationStatus, Optional[SecurityPolicyCandidateDTO], list[str], Optional[AIPolicyProposalRecord]]:
        """Translate natural language to a validated candidate, persisting proposal if db session is provided."""
        status, candidate_json, diagnostics = cls.translate_prompt_to_candidate(
            natural_language_input=natural_language_input,
            provider=provider,
            model_name=model_name,
        )

        candidate_dto: Optional[SecurityPolicyCandidateDTO] = None
        if candidate_json:
            try:
                candidate_dto = SecurityPolicyCandidateDTO.model_validate(candidate_json)
            except Exception:
                pass

        proposal_record: Optional[AIPolicyProposalRecord] = None
        if db is not None and candidate_json:
            policy_id = candidate_json.get("policy_id", f"POL-DRAFT-{int(datetime.now(timezone.utc).timestamp())}")
            # Ensure unique policy_id in case of collision
            existing = db.query(AIPolicyProposalRecord).filter_by(policy_id=policy_id).first()
            if existing:
                policy_id = f"{policy_id}-{int(datetime.now(timezone.utc).timestamp())}"
                candidate_json["policy_id"] = policy_id

            proposal_record = AIPolicyProposalRecord(
                policy_id=policy_id,
                natural_language_prompt=natural_language_input,
                generated_policy_json=candidate_json,
                validation_status=status.value,
                validation_diagnostics={"diagnostics": diagnostics},
                author_id=author_id,
            )
            db.add(proposal_record)
            db.commit()
            db.refresh(proposal_record)

        return status, candidate_dto, diagnostics, proposal_record

    @classmethod
    def approve_policy(
        cls,
        proposal_id: str,
        approved_by: str,
        db: Session,
        registry: Optional[SecurityPolicyRegistry] = None,
    ) -> SecurityPolicy:
        """Approve and activate an AI-generated policy candidate into the deterministic registry.

        Mandatory Human Approval Gate:
        - Must be approved by a verified reviewer/administrator.
        - Semantic validation is re-executed to guarantee invariant preservation.
        """
        proposal = db.query(AIPolicyProposalRecord).filter_by(id=proposal_id).first()
        if not proposal:
            proposal = db.query(AIPolicyProposalRecord).filter_by(policy_id=proposal_id).first()

        if not proposal:
            raise ValueError(f"AIPolicyProposalRecord '{proposal_id}' not found.")

        if proposal.approved_at is not None:
            raise ValueError(f"Policy '{proposal.policy_id}' has already been approved.")

        # Re-validate candidate JSON
        status, policy, diagnostics = SemanticPolicyValidator.validate(
            proposal.generated_policy_json,
            raw_prompt=proposal.natural_language_prompt,
        )

        if status != PolicyValidationStatus.VALIDATED_CANDIDATE or policy is None:
            raise ValueError(f"Cannot approve invalid policy: {diagnostics}")

        # Update proposal state
        proposal.approved_by = approved_by
        proposal.approved_at = datetime.now(timezone.utc)
        proposal.validation_status = "APPROVED_ACTIVE"
        db.commit()

        # Register in active SecurityPolicyRegistry if provided
        if registry is not None:
            registry.register_policy(policy)

        return policy
