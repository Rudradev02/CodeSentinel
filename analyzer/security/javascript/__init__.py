"""JavaScript, TypeScript, and React security rules catalog for CodeSentinel."""

from analyzer.security.javascript.sec_js_001_eval import RuleSecJs001
from analyzer.security.javascript.sec_js_002_function import RuleSecJs002
from analyzer.security.javascript.sec_js_003_dangerously_set_inner_html import RuleSecJs003
from analyzer.security.javascript.sec_js_004_client_secrets import RuleSecJs004
from analyzer.security.javascript.sec_js_005_unsafe_url import RuleSecJs005
from analyzer.security.javascript.sec_js_006_local_storage import RuleSecJs006

JAVASCRIPT_RULES = [
    RuleSecJs001(),
    RuleSecJs002(),
    RuleSecJs003(),
    RuleSecJs004(),
    RuleSecJs005(),
    RuleSecJs006(),
]

__all__ = [
    "RuleSecJs001",
    "RuleSecJs002",
    "RuleSecJs003",
    "RuleSecJs004",
    "RuleSecJs005",
    "RuleSecJs006",
    "JAVASCRIPT_RULES",
]
