"""Python and Django/Flask security rules catalog for CodeSentinel."""

from analyzer.security.python.sec_py_001_secrets import RuleSecPy001
from analyzer.security.python.sec_py_002_debug import RuleSecPy002
from analyzer.security.python.sec_py_003_subprocess import RuleSecPy003
from analyzer.security.python.sec_py_004_eval import RuleSecPy004
from analyzer.security.python.sec_py_005_sql import RuleSecPy005
from analyzer.security.python.sec_py_006_weak_hash import RuleSecPy006
from analyzer.security.python.sec_py_007_cors import RuleSecPy007
from analyzer.security.python.sec_py_008_csrf import RuleSecPy008
from analyzer.security.python.sec_py_009_sql_dataflow import RuleSecPy009
from analyzer.security.python.sec_py_010_subprocess_dataflow import RuleSecPy010
from analyzer.security.python.sec_py_011_sql_interprocedural import RuleSecPy011
from analyzer.security.python.sec_py_012_subprocess_interprocedural import RuleSecPy012

PYTHON_RULES = [
    RuleSecPy001(),
    RuleSecPy002(),
    RuleSecPy003(),
    RuleSecPy004(),
    RuleSecPy005(),
    RuleSecPy006(),
    RuleSecPy007(),
    RuleSecPy008(),
    RuleSecPy009(),
    RuleSecPy010(),
    RuleSecPy011(),
    RuleSecPy012(),
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
    "RuleSecPy009",
    "RuleSecPy010",
    "RuleSecPy011",
    "RuleSecPy012",
    "PYTHON_RULES",
]
