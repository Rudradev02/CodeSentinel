"""Python and Django/Flask security rules catalog for CodeSentinel."""

from analyzer.security.python.sec_py_001_secrets import RuleSecPy001
from analyzer.security.python.sec_py_002_debug import RuleSecPy002
from analyzer.security.python.sec_py_003_subprocess import RuleSecPy003
from analyzer.security.python.sec_py_004_eval import RuleSecPy004
from analyzer.security.python.sec_py_005_sql import RuleSecPy005
from analyzer.security.python.sec_py_006_weak_hash import RuleSecPy006
from analyzer.security.python.sec_py_007_cors import RuleSecPy007
from analyzer.security.python.sec_py_008_csrf import RuleSecPy008

PYTHON_RULES = [
    RuleSecPy001(),
    RuleSecPy002(),
    RuleSecPy003(),
    RuleSecPy004(),
    RuleSecPy005(),
    RuleSecPy006(),
    RuleSecPy007(),
    RuleSecPy008(),
]

__all__ = [
    "RuleSecPy001",
    "RuleSecPy002",
    "RuleSecPy003",
    "RuleSecPy004",
    "RuleSecPy005",
    "RuleSecPy006",
    "RuleSecPy007",
    "RuleSecPy008",
    "PYTHON_RULES",
]
