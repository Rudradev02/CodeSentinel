"""JavaScript, TypeScript, and React security rules catalog for CodeSentinel."""

from analyzer.security.javascript.sec_js_001_eval import RuleSecJs001
from analyzer.security.javascript.sec_js_002_function import RuleSecJs002
from analyzer.security.javascript.sec_js_003_dangerously_set_inner_html import RuleSecJs003
from analyzer.security.javascript.sec_js_004_client_secrets import RuleSecJs004
from analyzer.security.javascript.sec_js_005_unsafe_url import RuleSecJs005
from analyzer.security.javascript.sec_js_006_local_storage import RuleSecJs006
from analyzer.security.javascript.sec_js_007_dom_xss_dataflow import RuleSecJs007
from analyzer.security.javascript.sec_js_008_eval_dataflow import RuleSecJs008
from analyzer.security.javascript.sec_js_009_dom_xss_interprocedural import RuleSecJs009
from analyzer.security.javascript.sec_js_010_eval_interprocedural import RuleSecJs010

JAVASCRIPT_RULES = [
    RuleSecJs001(),
    RuleSecJs002(),
    RuleSecJs003(),
    RuleSecJs004(),
    RuleSecJs005(),
    RuleSecJs006(),
    RuleSecJs007(),
    RuleSecJs008(),
    RuleSecJs009(),
    RuleSecJs010(),
]

__all__ = [
    "RuleSecJs001",
    "RuleSecJs002",
    "RuleSecJs003",
    "RuleSecJs004",
    "RuleSecJs005",
    "RuleSecJs006",
    "RuleSecJs007",
    "RuleSecJs008",
    "RuleSecJs009",
    "RuleSecJs010",
    "JAVASCRIPT_RULES",
]
