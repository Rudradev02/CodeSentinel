"""Tests for AnalysisConfig model and RuleRegistry configuration application."""

import pytest
from pydantic import ValidationError

from analyzer.config.settings import AnalysisConfig, OutputFormat
from analyzer.models.findings import FindingSeverity
from analyzer.rules.registry import RuleRegistry


def test_analysis_config_defaults():
    config = AnalysisConfig()
    assert config.enabled_rules is None
    assert config.disabled_rules == []
    assert config.output_format == OutputFormat.TERMINAL
    assert config.output_file is None
    assert config.fail_on_severity is None
    assert config.arc_002_coupling_threshold == 10
    assert config.arc_003_loc_threshold == 500
    assert config.arc_003_fan_out_threshold == 8
    assert config.arc_003_fan_in_threshold == 5
    assert config.arc_004_depth_threshold == 5


def test_analysis_config_threshold_bounds():
    # Thresholds must be >= 1
    with pytest.raises(ValidationError):
        AnalysisConfig(arc_002_coupling_threshold=0)

    with pytest.raises(ValidationError):
        AnalysisConfig(arc_003_loc_threshold=-1)

    with pytest.raises(ValidationError):
        AnalysisConfig(arc_004_depth_threshold=0)


def test_analysis_config_output_format_normalization():
    cfg1 = AnalysisConfig(output_format="terminal")
    assert cfg1.output_format == OutputFormat.TERMINAL

    cfg2 = AnalysisConfig(output_format="text")
    assert cfg2.output_format == OutputFormat.TERMINAL

    cfg3 = AnalysisConfig(output_format="JSON")
    assert cfg3.output_format == OutputFormat.JSON

    with pytest.raises(ValidationError):
        AnalysisConfig(output_format="xml")


def test_analysis_config_fail_on_normalization():
    cfg1 = AnalysisConfig(fail_on_severity="high")
    assert cfg1.fail_on_severity == FindingSeverity.HIGH

    cfg2 = AnalysisConfig(fail_on_severity="CRITICAL")
    assert cfg2.fail_on_severity == FindingSeverity.CRITICAL

    with pytest.raises(ValidationError):
        AnalysisConfig(fail_on_severity="fatal")


def test_analysis_config_conflict_rejection():
    # Rule simultaneously enabled and disabled must raise ValueError
    with pytest.raises(ValidationError) as exc_info:
        AnalysisConfig(
            enabled_rules=["SEC-PY-001", "ARC-001"],
            disabled_rules=["SEC-PY-001"],
        )
    assert "Rule configuration conflict" in str(exc_info.value)


def test_analysis_config_permits_unknown_rule_ids_at_model_level():
    # Model represents configuration data; unknown rule IDs are not rejected here
    cfg = AnalysisConfig(
        enabled_rules=["NONEXISTENT-001"],
        disabled_rules=["NONEXISTENT-002"],
    )
    assert cfg.enabled_rules == ["NONEXISTENT-001"]
    assert cfg.disabled_rules == ["NONEXISTENT-002"]


def test_rule_registry_rejects_unknown_enabled_rule():
    registry = RuleRegistry(load_defaults=True)
    config = AnalysisConfig(enabled_rules=["FAKE-RULE-999"])

    with pytest.raises(ValueError) as exc_info:
        registry.apply_configuration(config)
    assert "Unknown rule ID(s) in enabled_rules" in str(exc_info.value)


def test_rule_registry_rejects_unknown_disabled_rule():
    registry = RuleRegistry(load_defaults=True)
    config = AnalysisConfig(disabled_rules=["FAKE-RULE-999"])

    with pytest.raises(ValueError) as exc_info:
        registry.apply_configuration(config)
    assert "Unknown rule ID(s) in disabled_rules" in str(exc_info.value)


def test_rule_registry_filter_enabled_rules_only():
    registry = RuleRegistry(load_defaults=True)
    config = AnalysisConfig(enabled_rules=["SEC-PY-001", "ARC-001"])
    registry.apply_configuration(config)

    # Only SEC-PY-001 and ARC-001 should remain
    assert registry.get_security_rule("SEC-PY-001") is not None
    assert registry.get_security_rule("SEC-PY-002") is None
    assert registry.get_architecture_rule("ARC-001") is not None
    assert registry.get_architecture_rule("ARC-002") is None


def test_rule_registry_filter_disabled_rules():
    registry = RuleRegistry(load_defaults=True)
    config = AnalysisConfig(disabled_rules=["SEC-PY-001", "ARC-001"])
    registry.apply_configuration(config)

    # SEC-PY-001 and ARC-001 should be disabled
    assert registry.get_security_rule("SEC-PY-001") is None
    assert registry.get_security_rule("SEC-PY-002") is not None
    assert registry.get_architecture_rule("ARC-001") is None
    assert registry.get_architecture_rule("ARC-002") is not None


def test_rule_registry_dynamic_threshold_overrides():
    registry = RuleRegistry(load_defaults=True)
    config = AnalysisConfig(
        arc_002_coupling_threshold=25,
        arc_003_loc_threshold=999,
        arc_004_depth_threshold=12,
    )
    registry.apply_configuration(config)

    rule_arc002 = registry.get_architecture_rule("ARC-002")
    assert rule_arc002.threshold == 25

    rule_arc003 = registry.get_architecture_rule("ARC-003")
    assert rule_arc003.loc_threshold_1 == 999

    rule_arc004 = registry.get_architecture_rule("ARC-004")
    assert rule_arc004.depth_threshold == 12
