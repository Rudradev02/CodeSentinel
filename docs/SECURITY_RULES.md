# CodeSentinel — Security Rules Specification

## 1. Philosophy & Evidence Categorization

CodeSentinel's security philosophy is grounded in **evidence-based static analysis**:
1. **Zero Hallucinated Vulnerabilities**: Detections must originate from concrete AST constructs, structural tokens, or strict heuristic patterns.
2. **Clear Evidence Categorization**:
   - **Deterministic**: Direct syntactic match via AST node traversal where the pattern is unambiguously dangerous or violating policy.
   - **Heuristic**: Structural or pattern match where risk depends on external context (e.g. data flow, configuration flags).
   - **AI-Assisted**: Supplemental explanation, contextual validation, or diff generation produced by LLM analysis of the static finding. The LLM is **never** the sole vulnerability detector.
3. **Conservative CWE/OWASP Attribution**: Standard mappings are applied only where the vulnerability directly satisfies the classification standard. We do NOT claim universal OWASP Top 10 coverage.

> [!NOTE]
> **Phase Status**: In **Phase 1**, this document defines the formal specification and test contracts for the initial security catalog. The rule base classes are implemented in `analyzer/security/base_rule.py`. Full rule implementations and test suites are developed in **Phase 3**.

---

## 2. Rule Definition Schema

Every rule in the CodeSentinel catalog adheres to the following metadata schema:

| Attribute | Type | Description |
| :--- | :--- | :--- |
| `rule_id` | `str` | Unique identifier formatted as `SEC-[LANG]-[0-9]{3}`. |
| `name` | `str` | Human-readable title of the rule. |
| `evidence_type`| `str` | `DETERMINISTIC` or `HEURISTIC`. |
| `severity` | `enum` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `confidence` | `enum` | `HIGH`, `MEDIUM`, `LOW`. |
| `languages` | `list[str]`| Targeted languages (e.g. `['python']`, `['javascript', 'typescript']`). |
| `frameworks` | `list[str]`| Associated frameworks (e.g. `['django']`, `['flask']`, `['react']`, or `['general']`). |
| `cwe_id` | `str` | Specific Common Weakness Enumeration ID (e.g. `CWE-78`, `CWE-79`). |
| `owasp_category`| `str` | OWASP Top 10 2021 category (e.g. `A03:2021-Injection`). |
| `detection_method` | `str`| `AST_NODE_MATCH`, `AST_CALL_VISITOR`, `REGEX_PATTERN`. |
| `remediation` | `str` | Clear actionable guidance to resolve the finding. |

---

## 3. Python, Django & Flask Rule Catalog

### 3.1 `SEC-PY-001`: Hardcoded Secrets & High-Entropy Credentials
- **Evidence Type**: `DETERMINISTIC` / `HEURISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-798 (Use of Hard-coded Credentials) | **OWASP**: A07:2021-Identification and Authentication Failures
- **Detection Method**: AST `Assign` visitor matching variable names (`SECRET_KEY`, `API_KEY`, `PASSWORD`, `AWS_SECRET_ACCESS_KEY`) assigned to non-empty string literals, combined with Shannon entropy scoring (> 4.5).
- **Positive Test Case**: `SECRET_KEY = "django-insecure-x%89234jklnsdf@#$234"`
- **Negative Test Case**: `SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")`
- **Remediation**: Extract secrets to environment variables or a dedicated secret management service.

### 3.2 `SEC-PY-002`: Production DEBUG Enabled
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-489 (Active Debug Code) | **OWASP**: A05:2021-Security Misconfiguration
- **Detection Method**: AST `Assign` matching `DEBUG = True` in settings files or `app.run(debug=True)` in Flask.
- **Positive Test Case**: `app.run(host="0.0.0.0", debug=True)`
- **Negative Test Case**: `DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")`
- **Remediation**: Set `DEBUG = False` in production configurations.

### 3.3 `SEC-PY-003`: Unsafe Subprocess Execution (`shell=True`)
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `CRITICAL` | **Confidence**: `HIGH`
- **CWE**: CWE-78 (OS Command Injection) | **OWASP**: A03:2021-Injection
- **Detection Method**: AST `Call` visitor targeting `subprocess.Popen`, `subprocess.call`, `subprocess.run` where keyword argument `shell=True` is supplied with a dynamic or formatted command argument.
- **Positive Test Case**: `subprocess.run(f"cat {user_file}", shell=True)`
- **Negative Test Case**: `subprocess.run(["cat", user_file], check=True, shell=False)`
- **Remediation**: Pass command and arguments as a sequence of strings and disable `shell=True`.

### 3.4 `SEC-PY-004`: Dangerous Dynamic Code Execution (`eval`/`exec`)
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `CRITICAL` | **Confidence**: `HIGH`
- **CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code) | **OWASP**: A03:2021-Injection
- **Detection Method**: AST `Call` visitor detecting built-in calls to `eval()`, `exec()`, or `ast.literal_eval` misuse.
- **Positive Test Case**: `result = eval(user_input_expression)`
- **Negative Test Case**: `result = json.loads(user_input_expression)`
- **Remediation**: Use structured serializers (JSON, YAML with safe loader) or explicit dispatch dictionaries.

### 3.5 `SEC-PY-005`: Raw SQL Query String Construction
- **Evidence Type**: `HEURISTIC`
- **Severity**: `HIGH` | **Confidence**: `MEDIUM`
- **CWE**: CWE-89 (SQL Injection) | **OWASP**: A03:2021-Injection
- **Detection Method**: AST `Call` matching cursor execution methods (`cursor.execute`, `connection.cursor().execute`) where the query argument is a `JoinedStr` (f-string), `BinOp` (`%` formatting or `+` concatenation), or `.format()` call.
- **Positive Test Case**: `cursor.execute(f"SELECT * FROM users WHERE email = '{user_email}'")`
- **Negative Test Case**: `cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))`
- **Remediation**: Use parameterized SQL placeholders or ORM query abstractions.

### 3.6 `SEC-PY-006`: Insecure Cryptographic Hash Functions
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `MEDIUM` | **Confidence**: `HIGH`
- **CWE**: CWE-328 (Use of Weak Hash) | **OWASP**: A02:2021-Cryptographic Failures
- **Detection Method**: AST `Call` visitor detecting `hashlib.md5()` or `hashlib.sha1()` without non-security `usedforsecurity=False` flag.
- **Positive Test Case**: `token = hashlib.md5(password.encode()).hexdigest()`
- **Negative Test Case**: `token = hashlib.sha256(data).hexdigest()` or `bcrypt.hashpw(...)`
- **Remediation**: Use modern cryptographic hash functions (SHA-256/SHA-512) for integrity and Argon2/bcrypt for passwords.

### 3.7 `SEC-PY-007`: Overly Permissive CORS Configuration
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-942 (Permissive Cross-origin Resource Sharing Policy) | **OWASP**: A01:2021-Broken Access Control
- **Detection Method**: AST inspection of `CORS_ALLOW_ALL_ORIGINS = True` (Django) or `CORS(app, origins="*")` combined with `supports_credentials=True` (Flask).
- **Positive Test Case**: `CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)`
- **Negative Test Case**: `CORS(app, resources={r"/*": {"origins": ["https://app.example.com"]}})`
- **Remediation**: Explicitly enumerate trusted origins and restrict credential sharing.

### 3.8 `SEC-PY-008`: Missing or Disabled CSRF Protection
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-352 (Cross-Site Request Forgery) | **OWASP**: A01:2021-Broken Access Control
- **Detection Method**: AST inspection detecting `@csrf_exempt` decorator on Django state-mutating views (POST, PUT, DELETE) or omission of `CsrfProtect(app)` in Flask-WTF.
- **Positive Test Case**: `@csrf_exempt\ndef transfer_funds(request): ...`
- **Negative Test Case**: Standard Django view protected with `csrf_protect` or standard CSRF middleware enabled.
- **Remediation**: Enforce anti-CSRF tokens for all state-changing endpoints.

---

## 4. JavaScript, TypeScript & React Rule Catalog

### 4.1 `SEC-JS-001`: Direct `eval()` Invocation
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `CRITICAL` | **Confidence**: `HIGH`
- **CWE**: CWE-95 | **OWASP**: A03:2021-Injection
- **Detection Method**: AST `CallExpression` matching callee `Identifier(eval)`.
- **Positive Test Case**: `const res = eval(payload);`
- **Negative Test Case**: `const res = JSON.parse(payload);`
- **Remediation**: Replace dynamic evaluation with typed parsers or object property lookups.

### 4.2 `SEC-JS-002`: Dynamic `Function` Constructor Execution
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `CRITICAL` | **Confidence**: `HIGH`
- **CWE**: CWE-95 | **OWASP**: A03:2021-Injection
- **Detection Method**: AST `NewExpression` or `CallExpression` targeting `Identifier(Function)`.
- **Positive Test Case**: `const fn = new Function('a', 'b', dynamicCode);`
- **Negative Test Case**: Standard function declarations or closures.
- **Remediation**: Refactor dynamic code to precompiled handler functions.

### 4.3 `SEC-JS-003`: React `dangerouslySetInnerHTML` Usage
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-79 (Cross-Site Scripting) | **OWASP**: A03:2021-Injection
- **Detection Method**: JSXAttribute visitor detecting `dangerouslySetInnerHTML` prop assigned without DOMPurify or equivalent sanitization wrapper.
- **Positive Test Case**: `<div dangerouslySetInnerHTML={{ __html: userBio }} />`
- **Negative Test Case**: `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userBio) }} />`
- **Remediation**: Avoid raw HTML insertion or sanitize thoroughly using DOMPurify.

### 4.4 `SEC-JS-004`: Hardcoded Client-Side Secrets
- **Evidence Type**: `DETERMINISTIC` / `HEURISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-798 | **OWASP**: A07:2021-Identification and Authentication Failures
- **Detection Method**: Variable declarations matching secret keywords (`apiKey`, `clientSecret`, `privateKey`) holding string literals with high entropy.
- **Positive Test Case**: `const stripeSecret = "sk_live_51Abc123...";`
- **Negative Test Case**: `const stripeKey = import.meta.env.VITE_STRIPE_PUBLIC_KEY;`
- **Remediation**: Secrets must never be exposed to frontend client bundles. Move secret operations to backend APIs.

### 4.5 `SEC-JS-005`: Unsafe URL Protocol Handling (`javascript:`)
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-79 (XSS) | **OWASP**: A03:2021-Injection
- **Detection Method**: JSX `href` or `src` attribute assignments where dynamic strings can evaluate to `javascript:` pseudo-protocols without protocol validation.
- **Positive Test Case**: `<a href={userProvidedUrl}>Website</a>` (where `userProvidedUrl` has no protocol check)
- **Negative Test Case**: `<a href={sanitizeUrl(userProvidedUrl)}>Website</a>`
- **Remediation**: Enforce protocol allowlisting (e.g. `https://`, `http://`) before rendering links.

### 4.6 `SEC-JS-006`: Sensitive Data Stored in `localStorage`
- **Evidence Type**: `HEURISTIC`
- **Severity**: `MEDIUM` | **Confidence**: `MEDIUM`
- **CWE**: CWE-922 (Insecure Storage of Sensitive Information) | **OWASP**: A04:2021-Insecure Design
- **Detection Method**: AST `CallExpression` to `localStorage.setItem` or `sessionStorage.setItem` where the key matches sensitive patterns (`token`, `auth`, `password`, `jwt`, `access_token`).
- **Positive Test Case**: `localStorage.setItem('auth_token', jwtToken);`
- **Negative Test Case**: `sessionStorage.setItem('theme_preference', 'dark');`
- **Remediation**: Store authentication tokens in `HttpOnly`, `SameSite=Strict` secure cookies to prevent XSS exfiltration.
