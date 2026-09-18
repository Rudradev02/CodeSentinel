"""Architecture rules catalog for CodeSentinel."""

from analyzer.architecture.rules.arc_001_circular import RuleArc001
from analyzer.architecture.rules.arc_002_coupling import RuleArc002
from analyzer.architecture.rules.arc_003_god_module import RuleArc003
from analyzer.architecture.rules.arc_004_deep_chain import RuleArc004
from analyzer.architecture.rules.arc_005_layer_inversion import RuleArc005
from analyzer.architecture.rules.arc_006_component_cycle import RuleArc006
from analyzer.architecture.rules.arc_007_sdp_violation import RuleArc007
from analyzer.architecture.rules.arc_008_orphan_export import RuleArc008

ARCHITECTURE_RULES = [
    RuleArc001(),
    RuleArc002(),
    RuleArc003(),
    RuleArc004(),
    RuleArc005(),
    RuleArc006(),
    RuleArc007(),
    RuleArc008(),
]

__all__ = [
    "RuleArc001",
    "RuleArc002",
    "RuleArc003",
    "RuleArc004",
    "RuleArc005",
    "RuleArc006",
    "RuleArc007",
    "RuleArc008",
    "ARCHITECTURE_RULES",
]

