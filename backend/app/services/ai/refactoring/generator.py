"""AI Architectural Refactoring Proposal Generator for Phase 30.

Synthesizes structured refactoring proposals for architectural smells (ARC-001 to ARC-009)
and executes deterministic simulation before presenting proposals to the user.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import uuid
from typing import Any, Optional
import networkx as nx
from sqlalchemy.orm import Session

from analyzer.architecture.refactoring_simulator import (
    DeterministicRefactoringSimulator,
    RefactoringProposalDTO,
    RefactoringType,
    SimulationResult,
)
from analyzer.models.graph import ComponentGraph
from backend.app.models.triage_feedback import AIRefactoringProposalRecord
from backend.app.services.ai.providers.base import BaseLLMProvider
from backend.app.services.ai.refactoring.context import ArchitectureContextExtractor, BoundedArchitectureContext

logger = logging.getLogger(__name__)

REFACTORING_SYSTEM_PROMPT = """You are CodeSentinel Software Architect.
Your task is to propose an architectural refactoring to eliminate a detected dependency smell (such as circular dependencies ARC-001/ARC-006 or coupling bottlenecks ARC-009).

CRITICAL RULES:
1. Output MUST be valid JSON strictly matching the RefactoringProposalDTO schema.
2. Select refactoring_type from:
   ["DEPENDENCY_INVERSION", "MODULE_EXTRACTION", "INTERFACE_INTRODUCTION", "CYCLE_BREAKING", "RESPONSIBILITY_SPLITTING", "BOUNDARY_CORRECTION"]
3. Specify hypothetical_edge_mutations with "action" ("REMOVE" or "ADD"), "source", and "target".
4. To break a cycle (A -> B -> A), introduce an interface/inversion or remove the backward coupling.
5. All proposals are purely advisory ("PROPOSAL_ONLY").
"""


class RefactoringProposalGenerator:
    """Generates structured refactoring proposals and verifies them through deterministic simulation."""

    @staticmethod
    def compute_context_hash(target_rule_id: str, components: list[str], cycle_path: list[str]) -> str:
        """Hash input context for proposal deduplication."""
        payload = {
            "target_rule_id": target_rule_id,
            "components": sorted(components),
            "cycle_path": cycle_path,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    @classmethod
    def generate_cycle_breaking_proposal(
        cls,
        graph_input: ComponentGraph | nx.DiGraph,
        cycle_path: list[str],
        target_rule_id: str = "ARC-006",
        provider: Optional[BaseLLMProvider] = None,
        model_name: Optional[str] = None,
        db: Optional[Session] = None,
        snapshot_id: Optional[str] = None,
        repository_id: Optional[str] = None,
    ) -> tuple[RefactoringProposalDTO, SimulationResult, Optional[AIRefactoringProposalRecord]]:
        """Generate a validated refactoring proposal to eliminate a cyclic dependency."""
        if len(cycle_path) < 2:
            raise ValueError("Cycle path must contain at least 2 components.")

        # Extract bounded context
        context = ArchitectureContextExtractor.extract_context(
            graph_input=graph_input,
            target_rule_id=target_rule_id,
            target_components=cycle_path,
            cycle_path=cycle_path,
        )

        proposal_id = f"REF-{str(uuid.uuid4())[:8].upper()}"

        # Default deterministic template: Dependency Inversion breaking the back-edge of the cycle
        u = cycle_path[-1]
        v = cycle_path[0]
        default_proposal = RefactoringProposalDTO(
            proposal_id=proposal_id,
            target_rule_id=target_rule_id,
            refactoring_type=RefactoringType.DEPENDENCY_INVERSION,
            title=f"Invert dependency from {u} to {v} via Interface",
            problem_statement=f"Circular dependency detected across cycle: {' -> '.join(cycle_path + [v])}.",
            proposed_design=(
                f"Extract interface in shared contract module. Have {u} depend on abstraction "
                f"rather than concrete implementation {v}, eliminating edge {u} -> {v}."
            ),
            affected_components=cycle_path,
            affected_files=[],
            hypothetical_edge_mutations=[
                {"action": "REMOVE", "source": u, "target": v}
            ],
            risks_and_tradeoffs=[
                "Requires introducing new abstract interface or factory",
                "Transient update required across dependency injection containers"
            ],
            compatibility_impact="BACKWARD_COMPATIBLE",
            test_requirements=[f"Verify contract compliance test for {u} and {v}"],
            status="PROPOSAL_ONLY",
        )

        proposal = default_proposal

        if provider is not None:
            user_prompt = (
                f"<architecture_context>\n"
                f"  <target_rule>{target_rule_id}</target_rule>\n"
                f"  <cycle_path>{' -> '.join(cycle_path)}</cycle_path>\n"
                f"  <nodes>{json.dumps(context.nodes)}</nodes>\n"
                f"  <edges>{json.dumps(context.edges)}</edges>\n"
                f"  <metrics>{json.dumps(context.metrics)}</metrics>\n"
                f"</architecture_context>\n"
                f"Propose a refactoring to eliminate this cycle. Return JSON."
            )
            try:
                response = provider.generate_sync(
                    prompt=user_prompt,
                    system_prompt=REFACTORING_SYSTEM_PROMPT,
                    model=model_name,
                    temperature=0.1,
                )
                candidate_data = response.parsed_json
                if candidate_data is None:
                    raw_text = response.raw_content.strip()
                    if raw_text.startswith("```"):
                        lines = raw_text.splitlines()
                        if lines[0].startswith("```"):
                            lines = lines[1:]
                        if lines and lines[-1].startswith("```"):
                            lines = lines[:-1]
                        raw_text = "\n".join(lines).strip()
                    candidate_data = json.loads(raw_text)

                if candidate_data and "hypothetical_edge_mutations" in candidate_data:
                    candidate_data["proposal_id"] = proposal_id
                    proposal = RefactoringProposalDTO.model_validate(candidate_data)
            except Exception as exc:
                logger.warning("AI refactoring generation fallback to deterministic template: %s", exc)

        # Execute deterministic simulation
        simulation_result = DeterministicRefactoringSimulator.simulate_proposal(
            graph_input=graph_input,
            proposal=proposal,
        )

        # Update expected metric deltas from ground-truth simulation
        proposal.expected_metric_deltas = simulation_result.metric_deltas

        proposal_record: Optional[AIRefactoringProposalRecord] = None
        if db is not None and snapshot_id and repository_id:
            context_hash = cls.compute_context_hash(target_rule_id, cycle_path, cycle_path)
            proposal_record = AIRefactoringProposalRecord(
                id=str(uuid.uuid4()),
                snapshot_id=snapshot_id,
                repository_id=repository_id,
                target_rule_id=proposal.target_rule_id,
                refactoring_type=proposal.refactoring_type.value,
                title=proposal.title,
                problem_statement=proposal.problem_statement,
                proposed_design=proposal.proposed_design,
                affected_components=proposal.affected_components,
                affected_files=proposal.affected_files,
                hypothetical_edge_mutations=proposal.hypothetical_edge_mutations,
                simulated_metric_deltas=simulation_result.metric_deltas,
                simulation_status=simulation_result.simulation_status,
                status="PROPOSAL_ONLY",
                context_hash=context_hash,
            )
            db.add(proposal_record)
            db.commit()
            db.refresh(proposal_record)

        return proposal, simulation_result, proposal_record
