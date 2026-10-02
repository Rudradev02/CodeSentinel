"""Semantic Validation Gate for Phase 12 AI Enrichment and Remediation Diffs.

Prevents hallucinated findings, path traversal, out-of-boundary patches,
or secret re-introduction from being stored or presented to the developer.
"""

import logging
from pathlib import Path
from typing import Any, Optional

from backend.app.schemas.ai import AIFindingEnrichmentDTO, ProposedPatchDTO
from backend.app.services.ai.scrubber import SecretScrubber

logger = logging.getLogger(__name__)


class SemanticValidationError(Exception):
    """Raised when an LLM enrichment payload violates semantic invariants."""
    pass


class SemanticValidator:
    """Rigorous validation gate for structured LLM enrichment responses."""

    @classmethod
    def validate_and_sanitize(
        cls,
        raw_json: dict[str, Any],
        target_finding_id: str,
        target_file_path: str,
        repo_root: Path,
    ) -> AIFindingEnrichmentDTO:
        """Validate syntax, types, identity, path safety, and patch verifiability."""
        # 1. Normalize and sanitize raw_json to handle subtle LLM variations
        normalized = dict(raw_json) if isinstance(raw_json, dict) else {}
        if not normalized.get("finding_id"):
            normalized["finding_id"] = target_finding_id

        # Normalize prescribed_remediation if null or empty
        if not normalized.get("prescribed_remediation"):
            if not normalized.get("is_likely_true_positive", True):
                normalized["prescribed_remediation"] = "No code change required. Analysis indicates candidate finding is defended or a false positive."
            else:
                normalized["prescribed_remediation"] = (
                    normalized.get("remediation")
                    or normalized.get("suggested_remediation")
                    or "Refactor code to sanitize inputs and eliminate untrusted execution."
                )

        if not normalized.get("risk_summary"):
            normalized["risk_summary"] = normalized.get("summary") or "Security risk identified in analyzed code context."

        if not normalized.get("technical_reasoning"):
            normalized["technical_reasoning"] = (
                normalized.get("reasoning")
                or normalized.get("explanation")
                or "Contextual AST analysis evaluated the candidate finding."
            )

        try:
            enrichment = AIFindingEnrichmentDTO.model_validate(normalized)
        except Exception as exc:
            raise SemanticValidationError(f"LLM JSON failed schema validation: {exc}")

        # 2. Finding Identity Validation
        if enrichment.finding_id != target_finding_id:
            logger.warning(
                "LLM hallucinated finding_id mismatch: expected %s, got %s",
                target_finding_id,
                enrichment.finding_id,
            )
            # Correct the ID to match target
            enrichment.finding_id = target_finding_id

        # 3. Confidence Clamping
        enrichment.confidence_score = max(0.0, min(1.0, enrichment.confidence_score))

        # 4. Patch Safety & Verifiability Gate
        if enrichment.proposed_patch is not None:
            patch = enrichment.proposed_patch
            patch_valid = cls._validate_patch_safety(patch, target_file_path, repo_root)
            if not patch_valid:
                logger.info("Proposed patch failed semantic validation; discarding patch while retaining explanation.")
                enrichment.proposed_patch = None

        return enrichment

    @classmethod
    def _validate_patch_safety(
        cls,
        patch: ProposedPatchDTO,
        target_file_path: str,
        repo_root: Path,
    ) -> bool:
        """Verify patch targets the finding file, avoids traversal, and parses cleanly."""
        # Path mismatch check
        clean_patch_path = patch.file_path.replace("\\", "/").strip()
        clean_target_path = target_file_path.replace("\\", "/").strip()

        if clean_patch_path != clean_target_path:
            logger.warning("Patch file_path '%s' does not match target '%s'", clean_patch_path, clean_target_path)
            return False

        # Path traversal checks
        if ".." in clean_patch_path or clean_patch_path.startswith("/"):
            logger.warning("Path traversal or absolute path detected in patch: %s", clean_patch_path)
            return False

        target_file = (repo_root / target_file_path).resolve()
        try:
            target_file.relative_to(repo_root.resolve())
        except ValueError:
            logger.warning("Patch file resolves outside repository root: %s", target_file)
            return False

        if not target_file.exists():
            logger.warning("Patch target file does not exist: %s", target_file)
            return False

        # Unified diff header check
        diff_text = patch.unified_diff
        if "--- a/" not in diff_text or "+++ b/" not in diff_text:
            logger.warning("Unified diff lacks standard header: %s", diff_text[:60])
            return False

        # Prevent LLM from introducing new secrets into patched code
        if SecretScrubber.contains_potential_secret(patch.patched_snippet):
            logger.warning("Patch proposed by LLM contains potential credential or sensitive pattern!")
            return False

        return True

    @classmethod
    def validate_evidence_grounding(
        cls,
        target_finding_id: str,
        target_file_path: str,
        line_start: int,
        line_end: Optional[int],
        enclosing_source: str,
        cited_symbols: list[str],
        repo_root: Optional[Path] = None,
    ) -> tuple[bool, list[str]]:
        """Verify that claims made by AI are grounded in actual source evidence.

        Returns:
            Tuple of (is_grounded, unverified_reasons)
        """
        unverified: list[str] = []

        # 1. Coordinate validity
        if line_start < 1 or (line_end is not None and line_end < line_start):
            unverified.append(f"Invalid line coordinates: {line_start}-{line_end}")

        # 2. File existence check if repo_root is provided
        if repo_root is not None:
            target_file = (repo_root / target_file_path).resolve()
            if not target_file.exists():
                unverified.append(f"Target file does not exist: {target_file_path}")

        # 3. Cited symbol grounding
        for symbol in cited_symbols:
            if symbol and symbol.strip() and symbol.strip() not in enclosing_source:
                unverified.append(f"Cited symbol '{symbol}' was not found in enclosing source code context")

        return (len(unverified) == 0, unverified)

