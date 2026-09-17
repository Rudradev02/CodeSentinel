"""Tests for Python/Django/Flask security rules (SEC-PY-001 through SEC-PY-008)."""

from analyzer.models.findings import EvidenceType, FindingConfidence, FindingSeverity
from analyzer.security.python.sec_py_001_secrets import RuleSecPy001
from analyzer.security.python.sec_py_002_debug import RuleSecPy002
from analyzer.security.python.sec_py_003_subprocess import RuleSecPy003
from analyzer.security.python.sec_py_004_eval import RuleSecPy004
from analyzer.security.python.sec_py_005_sql import RuleSecPy005
from analyzer.security.python.sec_py_006_weak_hash import RuleSecPy006
from analyzer.security.python.sec_py_007_cors import RuleSecPy007
from analyzer.security.python.sec_py_008_csrf import RuleSecPy008


# ==============================================================================
# SEC-PY-001: Hardcoded Secrets
# ==============================================================================
def test_sec_py_001_positive():
    rule = RuleSecPy001()
    code = 'SECRET_KEY = "django-insecure-x%89234jklnsdf@#$234"'
    findings = rule.analyze("settings.py", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-PY-001"
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].confidence == FindingConfidence.HIGH
    assert findings[0].evidence_type == EvidenceType.DETERMINISTIC
    assert findings[0].location.line_start == 1


def test_sec_py_001_negative_env_and_placeholder():
    rule = RuleSecPy001()
    safe_code = """
import os
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
API_KEY = "your-api-key"
PASSWORD = ""
DEBUG = True
"""
    findings = rule.analyze("settings.py", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-PY-002: Production DEBUG
# ==============================================================================
def test_sec_py_002_positive_assign():
    rule = RuleSecPy002()
    code = "DEBUG = True"
    findings = rule.analyze("settings.py", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-PY-002"
    assert findings[0].severity == FindingSeverity.HIGH


def test_sec_py_002_positive_flask_run():
    rule = RuleSecPy002()
    code = 'app.run(host="0.0.0.0", port=5000, debug=True)'
    findings = rule.analyze("app.py", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-PY-002"


def test_sec_py_002_negative():
    rule = RuleSecPy002()
    safe_code = """
import os
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")
DEBUG = False
app.run(debug=False)
"""
    findings = rule.analyze("settings.py", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-PY-003: Subprocess shell=True
# ==============================================================================
def test_sec_py_003_positive():
    rule = RuleSecPy003()
    code = 'subprocess.run(f"cat {user_file}", shell=True)'
    findings = rule.analyze("tasks.py", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-PY-003"
    assert findings[0].severity == FindingSeverity.CRITICAL


def test_sec_py_003_negative():
    rule = RuleSecPy003()
    safe_code = """
import subprocess
subprocess.run(["cat", user_file], check=True, shell=False)
subprocess.run(["ls", "-la"])
subprocess.call(["echo", "hello"])
"""
    findings = rule.analyze("tasks.py", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-PY-004: eval/exec
# ==============================================================================
def test_sec_py_004_positive():
    rule = RuleSecPy004()
    code = """
result = eval(user_input_expression)
exec(dynamic_code)
"""
    findings = rule.analyze("calc.py", code)
    assert len(findings) == 2
    assert all(f.rule_id == "SEC-PY-004" for f in findings)
    assert all(f.severity == FindingSeverity.CRITICAL for f in findings)


def test_sec_py_004_negative_safe_alternatives_and_method_calls():
    rule = RuleSecPy004()
    safe_code = """
import json
import ast

# Safe parsers
data = json.loads(payload)
value = ast.literal_eval(payload)

# Method calls on models/objects must NOT trigger
model.eval()
dataframe.eval("A + B")
"""
    findings = rule.analyze("calc.py", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-PY-005: Raw SQL String Construction
# ==============================================================================
def test_sec_py_005_positive():
    rule = RuleSecPy005()
    code = """
cursor.execute(f"SELECT * FROM users WHERE email = '{user_email}'")
cursor.raw("SELECT id FROM accounts WHERE name = '%s'" % account_name)
"""
    findings = rule.analyze("db.py", code)
    assert len(findings) == 2
    assert all(f.rule_id == "SEC-PY-005" for f in findings)
    assert all(f.evidence_type == EvidenceType.HEURISTIC for f in findings)


def test_sec_py_005_negative_parameterized_and_non_sql():
    rule = RuleSecPy005()
    safe_code = """
# Parameterized query with tuple
cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))
cursor.execute("SELECT 1")

# Non-SQL method call
task_executor.execute(task_function)
"""
    findings = rule.analyze("db.py", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-PY-006: Insecure Hash Functions
# ==============================================================================
def test_sec_py_006_positive():
    rule = RuleSecPy006()
    code = """
import hashlib
token = hashlib.md5(password.encode()).hexdigest()
digest = hashlib.sha1(data).digest()
h = hashlib.new("md5", b"data")
"""
    findings = rule.analyze("auth.py", code)
    assert len(findings) == 3
    assert all(f.rule_id == "SEC-PY-006" for f in findings)
    assert all(f.severity == FindingSeverity.MEDIUM for f in findings)


def test_sec_py_006_negative():
    rule = RuleSecPy006()
    safe_code = """
import hashlib

# Strong hashes
h256 = hashlib.sha256(data).hexdigest()
h512 = hashlib.sha512(data).hexdigest()

# MD5 explicitly marked for non-security checksum
checksum = hashlib.md5(file_data, usedforsecurity=False).hexdigest()
sha1_sum = hashlib.sha1(file_data, usedforsecurity=False).digest()
"""
    findings = rule.analyze("auth.py", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-PY-007: Overly Permissive CORS
# ==============================================================================
def test_sec_py_007_positive():
    rule = RuleSecPy007()
    django_code = "CORS_ALLOW_ALL_ORIGINS = True"
    flask_code = 'CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)'

    django_findings = rule.analyze("settings.py", django_code)
    assert len(django_findings) == 1
    assert django_findings[0].rule_id == "SEC-PY-007"

    flask_findings = rule.analyze("app.py", flask_code)
    assert len(flask_findings) == 1
    assert flask_findings[0].rule_id == "SEC-PY-007"


def test_sec_py_007_negative():
    rule = RuleSecPy007()
    safe_code = """
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
CORS(app, resources={r"/*": {"origins": ["https://app.example.com"]}})
"""
    findings = rule.analyze("settings.py", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-PY-008: Disabled CSRF (@csrf_exempt)
# ==============================================================================
def test_sec_py_008_positive():
    rule = RuleSecPy008()
    code = """
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def transfer_funds(request):
    return JsonResponse({'status': 'ok'})
"""
    findings = rule.analyze("views.py", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-PY-008"
    assert findings[0].severity == FindingSeverity.HIGH


def test_sec_py_008_negative():
    rule = RuleSecPy008()
    safe_code = """
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def transfer_funds(request):
    return JsonResponse({'status': 'ok'})

def standard_view(request):
    return JsonResponse({'status': 'ok'})
"""
    findings = rule.analyze("views.py", safe_code)
    assert len(findings) == 0
