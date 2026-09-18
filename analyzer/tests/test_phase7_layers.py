"""Unit tests for Architectural Tier Classification and Layer Boundary Enforcement."""

from pathlib import Path
from analyzer.architecture.layers import (
    ArchitecturalTier,
    LayerBoundaryAnalyzer,
    DEFAULT_PROHIBITED_DEPENDENCIES,
    classify_component_layer,
)
from analyzer.engine.pipeline import AnalysisPipeline


def test_classify_component_layer_patterns():
    # Presentation patterns
    assert classify_component_layer("frontend.views") == ArchitecturalTier.PRESENTATION
    assert classify_component_layer("api.controllers") == ArchitecturalTier.PRESENTATION
    assert classify_component_layer("web.routes") == ArchitecturalTier.PRESENTATION
    assert classify_component_layer("ui.components") == ArchitecturalTier.PRESENTATION

    # Application patterns
    assert classify_component_layer("app.services") == ArchitecturalTier.APPLICATION
    assert classify_component_layer("usecases.billing") == ArchitecturalTier.APPLICATION
    assert classify_component_layer("handlers.auth") == ArchitecturalTier.APPLICATION

    # Domain patterns
    assert classify_component_layer("domain.user") == ArchitecturalTier.DOMAIN
    assert classify_component_layer("entities.order") == ArchitecturalTier.DOMAIN
    assert classify_component_layer("models.account") == ArchitecturalTier.DOMAIN

    # Infrastructure patterns
    assert classify_component_layer("infrastructure.db") == ArchitecturalTier.INFRASTRUCTURE
    assert classify_component_layer("repositories.user_repo") == ArchitecturalTier.INFRASTRUCTURE
    assert classify_component_layer("adapters.redis") == ArchitecturalTier.INFRASTRUCTURE
    assert classify_component_layer("database.postgres") == ArchitecturalTier.INFRASTRUCTURE

    # Unknown patterns should remain None
    assert classify_component_layer("unknown_utility_box") is None
    assert classify_component_layer("xyz123") is None
    assert classify_component_layer("root") is None


def test_prohibited_rules_coverage():
    # Ensure all core architectural violations are defined
    assert (ArchitecturalTier.DOMAIN.value, ArchitecturalTier.INFRASTRUCTURE.value) in DEFAULT_PROHIBITED_DEPENDENCIES
    assert (ArchitecturalTier.DOMAIN.value, ArchitecturalTier.PRESENTATION.value) in DEFAULT_PROHIBITED_DEPENDENCIES
    assert (ArchitecturalTier.INFRASTRUCTURE.value, ArchitecturalTier.PRESENTATION.value) in DEFAULT_PROHIBITED_DEPENDENCIES
    assert (ArchitecturalTier.INFRASTRUCTURE.value, ArchitecturalTier.APPLICATION.value) in DEFAULT_PROHIBITED_DEPENDENCIES


def test_clean_layered_project_has_no_inversions():
    clean_repo = Path(__file__).resolve().parent / "fixtures" / "phase7" / "layered_clean_project"
    pipeline = AnalysisPipeline()
    result = pipeline.run(str(clean_repo))
    
    inversion_findings = [f for f in result.architecture_findings if f.rule_id == "ARC-005"]
    assert len(inversion_findings) == 0


def test_inverted_layered_project_detects_violations():
    inverted_repo = Path(__file__).resolve().parent / "fixtures" / "phase7" / "layered_inverted_project"
    pipeline = AnalysisPipeline()
    result = pipeline.run(str(inverted_repo))
    
    inversion_findings = [f for f in result.architecture_findings if f.rule_id == "ARC-005"]
    assert len(inversion_findings) >= 2
    
    # Check that DOMAIN -> INFRASTRUCTURE and INFRASTRUCTURE -> PRESENTATION were caught
    reasons = [f.evidence.get("rule_description", "") for f in inversion_findings]
    assert any("DOMAIN" in r and "INFRASTRUCTURE" in r for r in reasons)
    assert any("INFRASTRUCTURE" in r and "PRESENTATION" in r for r in reasons)
