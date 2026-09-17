"""Tests for JavaScript, TypeScript, and React security rules (SEC-JS-001 through SEC-JS-006)."""

from analyzer.models.findings import EvidenceType, FindingConfidence, FindingSeverity
from analyzer.security.javascript.sec_js_001_eval import RuleSecJs001
from analyzer.security.javascript.sec_js_002_function import RuleSecJs002
from analyzer.security.javascript.sec_js_003_dangerously_set_inner_html import RuleSecJs003
from analyzer.security.javascript.sec_js_004_client_secrets import RuleSecJs004
from analyzer.security.javascript.sec_js_005_unsafe_url import RuleSecJs005
from analyzer.security.javascript.sec_js_006_local_storage import RuleSecJs006


# ==============================================================================
# SEC-JS-001: Direct eval() Invocation
# ==============================================================================
def test_sec_js_001_positive():
    rule = RuleSecJs001()
    code = "const res = eval(payload);"
    findings = rule.analyze("app.js", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-JS-001"
    assert findings[0].severity == FindingSeverity.CRITICAL


def test_sec_js_001_negative_json_parse_and_member():
    rule = RuleSecJs001()
    safe_code = """
const res = JSON.parse(payload);
const val = mathEngine.eval(expression);
"""
    findings = rule.analyze("app.js", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-JS-002: Dynamic Function Constructor
# ==============================================================================
def test_sec_js_002_positive():
    rule = RuleSecJs002()
    code = "const fn = new Function('a', 'b', dynamicCode);"
    findings = rule.analyze("compiler.ts", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-JS-002"
    assert findings[0].severity == FindingSeverity.CRITICAL


def test_sec_js_002_negative_functions_and_types():
    rule = RuleSecJs002()
    safe_code = """
function calculateTotal(a, b) { return a + b; }
const arrowFn = (x) => x * 2;
const callback: Function = () => {};
"""
    findings = rule.analyze("types.ts", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-JS-003: dangerouslySetInnerHTML
# ==============================================================================
def test_sec_js_003_positive_unsanitized():
    rule = RuleSecJs003()
    code = '<div dangerouslySetInnerHTML={{ __html: input }} />'
    findings = rule.analyze("Profile.tsx", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-JS-003"
    assert findings[0].severity == FindingSeverity.HIGH


def test_sec_js_003_positive_sanitized_via_dompurify():
    rule = RuleSecJs003()
    code = """
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(input);
export function Bio() {
    return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
"""
    findings = rule.analyze("Profile.tsx", code)
    # Correctly sanitized: should produce NO finding
    assert len(findings) == 0


def test_sec_js_003_negative_relationship_test():
    rule = RuleSecJs003()
    # Even though DOMPurify is in the file, the value assigned to __html is 'html' (unsanitized)
    code = """
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(input);
const html = input;
export function Bio() {
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
"""
    findings = rule.analyze("Profile.tsx", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-JS-003"


# ==============================================================================
# SEC-JS-004: Hardcoded Client-Side Secrets
# ==============================================================================
def test_sec_js_004_positive():
    rule = RuleSecJs004()
    code = 'const clientSecret = "custom_mock_secret_token_1234567890_abcdef";'
    findings = rule.analyze("config.ts", code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-JS-004"
    assert findings[0].severity == FindingSeverity.HIGH


def test_sec_js_004_negative_env_and_public_keys():
    rule = RuleSecJs004()
    safe_code = """
const stripeKey = import.meta.env.VITE_STRIPE_PUBLIC_KEY;
const apiUrl = process.env.REACT_APP_API_URL;
const label = "api_key_label";
const publicKey = "pk_live_public_safe";
"""
    findings = rule.analyze("config.ts", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-JS-005: Unsafe URL Protocol (javascript:)
# ==============================================================================
def test_sec_js_005_positive():
    rule = RuleSecJs005()
    code = """
export function Links() {
    return (
        <div>
            <a href="javascript:alert(1)">Click Me</a>
            <a href={`javascript:${payload}`}>Dynamic</a>
        </div>
    );
}
"""
    findings = rule.analyze("Nav.tsx", code)
    assert len(findings) == 2
    assert all(f.rule_id == "SEC-JS-005" for f in findings)


def test_sec_js_005_negative_generic_dynamic_and_safe_urls():
    rule = RuleSecJs005()
    # As mandated by user instruction #5: generic <a href={url}> must NOT become a finding!
    safe_code = """
export function SafeLinks({ url, userProvidedUrl }) {
    return (
        <div>
            <a href={url}>Dynamic Link</a>
            <a href={userProvidedUrl}>User Profile</a>
            <a href="https://example.com">Static Secure</a>
            <a href="/dashboard">Internal Path</a>
        </div>
    );
}
"""
    findings = rule.analyze("Nav.tsx", safe_code)
    assert len(findings) == 0


# ==============================================================================
# SEC-JS-006: Sensitive Data in LocalStorage
# ==============================================================================
def test_sec_js_006_positive():
    rule = RuleSecJs006()
    code = """
localStorage.setItem('auth_token', jwtToken);
sessionStorage.setItem('access_token', token);
window.localStorage.setItem('user_password', secret);
"""
    findings = rule.analyze("auth.js", code)
    assert len(findings) == 3
    assert all(f.rule_id == "SEC-JS-006" for f in findings)
    assert all(f.severity == FindingSeverity.MEDIUM for f in findings)


def test_sec_js_006_negative():
    rule = RuleSecJs006()
    safe_code = """
sessionStorage.setItem('theme_preference', 'dark');
localStorage.setItem('sidebar_collapsed', 'true');
const token = localStorage.getItem('auth_token');
"""
    findings = rule.analyze("storage.js", safe_code)
    assert len(findings) == 0
