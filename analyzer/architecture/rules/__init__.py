"""Architecture rules catalog for CodeSentinel."""

from analyzer.architecture.rules.arc_001_circular import RuleArc001
from analyzer.architecture.rules.arc_002_coupling import RuleArc002
from analyzer.architecture.rules.arc_003_god_module import RuleArc003
from analyzer.architecture.rules.arc_004_deep_chain import RuleArc004

ARCHITECTURE_RULES = [
    RuleArc001(),
    RuleArc002(),
    RuleArc003(),
    RuleArc004(),
]

__all__ = [
    "RuleArc001",
    "RuleArc002",
    "RuleArc003",
    "RuleArc004",
    "ARCHITECTURE_RULES",
]
