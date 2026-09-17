"""Registry for discovering, querying, and managing security and architecture rules."""

from typing import Optional

from analyzer.architecture.base_rule import BaseArchitectureRule
from analyzer.architecture.rules import (
    ARCHITECTURE_RULES,
    RuleArc002,
    RuleArc003,
    RuleArc004,
)
from analyzer.config.settings import AnalysisConfig
from analyzer.models.findings import RuleDefinition
from analyzer.security.base_rule import BaseSecurityRule
from analyzer.security.javascript import JAVASCRIPT_RULES
from analyzer.security.python import PYTHON_RULES


class RuleRegistry:
    """Registry maintaining available security and architecture rules."""

    def __init__(self, load_defaults: bool = True):
        self._security_rules: dict[str, BaseSecurityRule] = {}
        self._architecture_rules: dict[str, BaseArchitectureRule] = {}

        if load_defaults:
            for rule in PYTHON_RULES + JAVASCRIPT_RULES:
                self.register_security_rule(rule)
            for rule in ARCHITECTURE_RULES:
                self.register_architecture_rule(rule)

    def register_security_rule(self, rule: BaseSecurityRule) -> None:
        """Register an instance of BaseSecurityRule."""
        self._security_rules[rule.rule_id] = rule

    def register_architecture_rule(self, rule: BaseArchitectureRule) -> None:
        """Register an instance of BaseArchitectureRule."""
        self._architecture_rules[rule.rule_id] = rule

    def get_security_rule(self, rule_id: str) -> Optional[BaseSecurityRule]:
        """Look up a security rule by rule_id."""
        return self._security_rules.get(rule_id)

    def get_architecture_rule(self, rule_id: str) -> Optional[BaseArchitectureRule]:
        """Look up an architecture rule by rule_id."""
        return self._architecture_rules.get(rule_id)

    def get_rule_definitions(self) -> list[RuleDefinition]:
        """Return definitions for all registered rules."""
        defs: list[RuleDefinition] = []
        for r in self._security_rules.values():
            defs.append(r.get_definition())
        for r in self._architecture_rules.values():
            defs.append(r.get_definition())
        return defs

    def get_applicable_security_rules(
        self,
        language: str,
        detected_frameworks: Optional[list[str]] = None,
    ) -> list[BaseSecurityRule]:
        """Filter registered security rules applicable to the given language and frameworks.
        
        Args:
            language: Discovered file language (e.g. 'PYTHON', 'JAVASCRIPT', 'TYPESCRIPT').
            detected_frameworks: List of repository-level detected frameworks (e.g. ['django', 'flask', 'react']).
            
        Returns:
            List of applicable BaseSecurityRule instances.
        """
        lang_lower = language.lower()
        active_fws = set(f.lower() for f in (detected_frameworks or []))

        applicable: list[BaseSecurityRule] = []
        for rule in self._security_rules.values():
            # 1. Language matching
            rule_langs = [l.lower() for l in rule.languages]
            if rule_langs and lang_lower not in rule_langs:
                continue

            # 2. Framework matching
            if not rule.frameworks or "general" in rule.frameworks:
                applicable.append(rule)
                continue

            # Rule requires specific framework(s)
            rule_fws = set(f.lower() for f in rule.frameworks)
            if active_fws.intersection(rule_fws):
                applicable.append(rule)

        return applicable

    def get_all_architecture_rules(self) -> list[BaseArchitectureRule]:
        """Return all registered architecture rules."""
        return list(self._architecture_rules.values())

    def apply_configuration(self, config: AnalysisConfig) -> None:
        """Apply user configuration to validate and filter active rules and configure thresholds.
        
        Validates rule IDs against all registered rules, rejecting unknown IDs.
        Filters rules based on enabled_rules whitelist and disabled_rules blacklist.
        Configures dynamic architecture thresholds.
        """
        all_registered = set(self._security_rules.keys()) | set(self._architecture_rules.keys())

        # Validate unknown rule IDs at registry boundary
        if config.enabled_rules is not None:
            unknown_enabled = [r for r in config.enabled_rules if r not in all_registered]
            if unknown_enabled:
                raise ValueError(
                    f"Unknown rule ID(s) in enabled_rules: {sorted(unknown_enabled)}. "
                    f"Valid registered rules: {sorted(list(all_registered))}"
                )

        if config.disabled_rules:
            unknown_disabled = [r for r in config.disabled_rules if r not in all_registered]
            if unknown_disabled:
                raise ValueError(
                    f"Unknown rule ID(s) in disabled_rules: {sorted(unknown_disabled)}. "
                    f"Valid registered rules: {sorted(list(all_registered))}"
                )

        # Calculate active rule IDs
        if config.enabled_rules is not None:
            active_ids = set(config.enabled_rules) - set(config.disabled_rules)
        else:
            active_ids = all_registered - set(config.disabled_rules)

        self._security_rules = {
            rule_id: rule
            for rule_id, rule in self._security_rules.items()
            if rule_id in active_ids
        }
        self._architecture_rules = {
            rule_id: rule
            for rule_id, rule in self._architecture_rules.items()
            if rule_id in active_ids
        }

        # Apply custom thresholds to active architecture rules
        if "ARC-002" in self._architecture_rules:
            self._architecture_rules["ARC-002"] = RuleArc002(
                threshold=config.arc_002_coupling_threshold
            )

        if "ARC-003" in self._architecture_rules:
            self._architecture_rules["ARC-003"] = RuleArc003(
                loc_threshold_1=config.arc_003_loc_threshold,
                fan_out_threshold_1=config.arc_003_fan_out_threshold,
                fan_in_threshold_1=config.arc_003_fan_in_threshold,
                loc_threshold_2=config.arc_003_loc_threshold_2,
                fan_out_threshold_2=config.arc_003_fan_out_threshold_2,
            )

        if "ARC-004" in self._architecture_rules:
            self._architecture_rules["ARC-004"] = RuleArc004(
                depth_threshold=config.arc_004_depth_threshold
            )

