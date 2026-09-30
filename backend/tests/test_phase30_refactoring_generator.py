"""Integration tests for Phase 30 AI Architectural Refactoring Generator and DB persistence."""

import networkx as nx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.db.base import Base
from backend.app.models.repository import Repository
from backend.app.models.snapshot import AnalysisSnapshot
from backend.app.models.triage_feedback import AIRefactoringProposalRecord
from backend.app.services.ai.refactoring.generator import RefactoringProposalGenerator


@pytest.fixture
def sqlite_db():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def cyclic_component_graph():
    """Builds a 3-node cyclic component graph: A -> B -> C -> A."""
    G = nx.DiGraph()
    G.add_node("comp_a", layer="domain", files=["a1.py", "a2.py"])
    G.add_node("comp_b", layer="services", files=["b1.py"])
    G.add_node("comp_c", layer="infrastructure", files=["c1.py"])

    G.add_edge("comp_a", "comp_b")
    G.add_edge("comp_b", "comp_c")
    G.add_edge("comp_c", "comp_a")  # Cycle back-edge
    return G


def test_refactoring_generator_and_persistence(cyclic_component_graph, sqlite_db):
    """Verifies proposal generator integration, simulation execution, and DB persistence."""
    repo = Repository(id="repo-ref-30", name="repo-ref-30", path="/test/repo")
    sqlite_db.add(repo)
    snap = AnalysisSnapshot(id="snap-ref-30", repository_id="repo-ref-30")
    sqlite_db.add(snap)
    sqlite_db.commit()

    proposal, sim_result, db_record = RefactoringProposalGenerator.generate_cycle_breaking_proposal(
        graph_input=cyclic_component_graph,
        cycle_path=["comp_a", "comp_b", "comp_c"],
        target_rule_id="ARC-006",
        db=sqlite_db,
        snapshot_id=snap.id,
        repository_id=repo.id,
    )

    assert proposal is not None
    assert proposal.status == "PROPOSAL_ONLY"
    assert sim_result.simulation_status == "VERIFIED_SIMULATION"
    assert db_record is not None

    # Check persistence in database
    retrieved = sqlite_db.query(AIRefactoringProposalRecord).filter_by(id=db_record.id).first()
    assert retrieved is not None
    assert retrieved.target_rule_id == "ARC-006"
    assert retrieved.simulation_status == "VERIFIED_SIMULATION"
    assert retrieved.status == "PROPOSAL_ONLY"
