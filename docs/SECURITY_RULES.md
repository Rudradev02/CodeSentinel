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
> **Phase Status**: In **Phase 5**, all 14 security rules and 4 architecture rules have been enriched with structured evidence payloads, centralized rule metadata (`rationale`, `supported_languages`), deterministic finding deduplication, secret redaction, and CLI rule inspection via `codesentinel rules`.

---

## 2. Severity vs. Confidence

CodeSentinel maintains a strict conceptual separation between **Severity** and **Confidence**:

### Severity (Impact Rating)
Measures the potential organizational, operational, or security damage if the defect is exploited or unaddressed:
- `CRITICAL`: Immediate compromise (e.g. dynamic code execution via `eval`/`exec`, unauthenticated command injection via `shell=True`).
- `HIGH`: Major security defect or structural anti-pattern (e.g. hardcoded secrets, raw SQL construction, circular dependency cycles, god modules).
- `MEDIUM`: Moderate security flaw or coupling friction (e.g. insecure hashes, local storage credentials, excessive fan-out).
- `LOW`: Minor hygiene issue or maintainability smell (e.g. deep dependency chains).
- `INFO`: Informational observation.

### Confidence (Static Evidence Strength)
Measures the strength and specificity of the **static AST/structural evidence**:
- `HIGH`: Unambiguous AST construct or deterministic graph cycle where pattern matching is exact.
- `MEDIUM`: Context-dependent pattern or structural heuristic where applicability depends on runtime flow or coupling thresholds.
- `LOW`: Speculative or weak static indicator.

> [!IMPORTANT]
> **What Confidence is NOT**: Confidence is NOT a statistical probability, a machine-learning score, or mathematical proof of runtime exploitability. CodeSentinel never employs machine learning for primary rule detection.

---

## 3. Secret Redaction Guarantees

For sensitive findings (`SEC-PY-001` and `SEC-JS-004`), CodeSentinel enforces deterministic masking:
- Full credential values are **never** emitted in finding descriptions, messages, structured evidence, code snippets, terminal reports, or JSON outputs.
- Secrets $\le 6$ characters are masked as `***`.
- Secrets $> 6$ characters preserve only the first 3 and last 2 characters (e.g., `AKIAIOSFODNN7EXAMPLE12` becomes `AKI...12`).
- Redaction is applied by the detecting rule at source to avoid corrupting unrelated code snippets.

---

## 4. Rule Definition Schema

Every rule in the CodeSentinel catalog adheres to the following metadata schema managed in `analyzer/rules/registry.py`:

| Attribute | Type | Description |
| :--- | :--- | :--- |
| `rule_id` | `str` | Unique identifier formatted as `SEC-[LANG]-[0-9]{3}` or `ARC-[0-9]{3}`. |
| `name` | `str` | Human-readable title of the rule. |
| `category` | `enum` | `SECURITY` or `ARCHITECTURE`. |
| `evidence_type`| `enum` | `DETERMINISTIC` or `HEURISTIC`. |
| `severity` | `enum` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `confidence` | `enum` | `HIGH`, `MEDIUM`, `LOW`. |
| `description` | `str` | Detailed explanation of what pattern was detected. |
| `rationale` | `str` | Architectural or security impact justification. |
| `remediation` | `str` | Clear, actionable guidance to resolve the finding. |
| `supported_languages` | `list[str]`| Targeted languages (e.g. `['python']`, `['javascript', 'typescript']`). |
| `frameworks` | `list[str]`| Associated frameworks (e.g. `['django']`, `['flask']`, `['react']`, or `['general']`). |
| `cwe_id` | `Optional[str]` | Specific Common Weakness Enumeration ID (e.g. `CWE-78`, `CWE-79`). |
| `owasp_category`| `Optional[str]` | OWASP Top 10 2021 category (e.g. `A03:2021-Injection`). |

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

### 3.9 `SEC-PY-009`: SQL Injection via Data-Flow
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-89 (SQL Injection) | **OWASP**: A03:2021-Injection
- **Detection Method**: Intraprocedural data-flow analysis tracing untrusted inputs (`request.args`, `request.form`, `request.GET`, `os.environ`) through definitions, reassignments, concatenations, and f-strings reaching raw SQL execution sinks (`cursor.execute`, `session.execute`).
- **Sanitizers & Neutralizers**: Parameterized query bindings (safe sink usage) or context-specific numeric casts (`int()`, `float()`).
- **Evidence Schema**: `flow_type: INTRA_PROCEDURAL_TAINT`, `source`, `propagation` steps, `sanitizer`, `sink`, `path_summary`.
- **Remediation**: Use parameterized query placeholders or ORM query builders instead of multi-step string composition.

### 3.10 `SEC-PY-010`: Command Injection via Data-Flow
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-78 (OS Command Injection) | **OWASP**: A03:2021-Injection
- **Detection Method**: Intraprocedural data-flow tracking from untrusted sources into subprocess execution sinks (`subprocess.run`, `subprocess.Popen`, `os.system`).
- **Sanitizers & Neutralizers**: Shell quoting with `shlex.quote()`.
- **Evidence Schema**: `flow_type: INTRA_PROCEDURAL_TAINT`, `source`, `propagation` steps, `sanitizer`, `sink`, `path_summary`.
- **Remediation**: Pass command arguments as discrete argument lists without `shell=True`, or quote arguments using `shlex.quote()`.

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
- **Positive Test Case**: `const clientSecret = "custom_mock_secret_token_1234567890_abcdef";`
- **Negative Test Case**: `const stripeKey = import.meta.env.VITE_STRIPE_PUBLIC_KEY;`
- **Remediation**: Secrets must never be exposed to frontend client bundles. Move secret operations to backend APIs.

### 4.5 `SEC-JS-005`: Unsafe URL Protocol Handling (`javascript:`)
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-79 (XSS) | **OWASP**: A03:2021-Injection
- **Detection Method**: JSX `href` or `src` attribute assignments where the value is statically established to use or construct a `javascript:` pseudo-protocol URL (e.g. literal string `"javascript:..."`, template string `` `javascript:${...}` ``, or string concatenation `{"javascript:" + ...}`).
- **Positive Test Case**: `<a href="javascript:alert(1)">Click</a>` or `<a href={`javascript:${payload}`}>Run</a>`
- **Negative Test Case**: `<a href={url}>Dynamic</a>` (unresolved protocol is NOT falsely flagged) or `<a href="https://example.com">Website</a>`
- **Remediation**: Enforce protocol allowlisting (e.g. `https://`, `http://`, `mailto:`) before rendering links. Never allow `javascript:` schemes.

### 4.6 `SEC-JS-006`: Sensitive Data Stored in `localStorage`
- **Evidence Type**: `HEURISTIC`
- **Severity**: `MEDIUM` | **Confidence**: `MEDIUM`
- **CWE**: CWE-922 (Insecure Storage of Sensitive Information) | **OWASP**: A04:2021-Insecure Design
- **Detection Method**: AST `CallExpression` to `localStorage.setItem` or `sessionStorage.setItem` where the storage key matches sensitive patterns (`token`, `auth`, `password`, `jwt`, `access_token`, `credential`, `api_key`).
- **Positive Test Case**: `localStorage.setItem('auth_token', jwtToken);`
- **Negative Test Case**: `sessionStorage.setItem('theme_preference', 'dark');`
- **Remediation**: Store authentication tokens in `HttpOnly`, `SameSite=Strict` secure cookies to prevent XSS exfiltration.

### 4.7 `SEC-JS-007`: DOM-based Cross-Site Scripting via Data-Flow
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **CWE**: CWE-79 (Cross-Site Scripting) | **OWASP**: A03:2021-Injection
- **Detection Method**: Intraprocedural data-flow analysis tracing untrusted browser sources (`location.search`, `location.hash`, `document.referrer`) to raw DOM injection sinks (`element.innerHTML`, `element.outerHTML`).
- **Sanitizers & Neutralizers**: Sanitization using `DOMPurify.sanitize()`.
- **Evidence Schema**: `flow_type: INTRA_PROCEDURAL_TAINT`, `source`, `propagation` steps, `sanitizer`, `sink`, `path_summary`.
- **Remediation**: Sanitize untrusted input using `DOMPurify.sanitize()` or assign text safely via `textContent` or `innerText`.

### 4.8 `SEC-JS-008`: Dynamic Code Execution via Data-Flow
- **Evidence Type**: `CRITICAL`
- **Severity**: `CRITICAL` | **Confidence**: `HIGH`
- **CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code) | **OWASP**: A03:2021-Injection
- **Detection Method**: Intraprocedural data-flow analysis tracing untrusted inputs across intermediate variables and string concatenations into `eval()` or `Function()` constructor sinks.
- **Evidence Schema**: `flow_type: INTRA_PROCEDURAL_TAINT`, `source`, `propagation` steps, `sanitizer`, `sink`, `path_summary`.
- **Remediation**: Parse untrusted inputs with strict formats like `JSON.parse()`; avoid evaluating dynamic code.

---

## 5. Architecture Rules Catalog

### 5.1 `ARC-001`: Circular Dependency Cycle
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **Detection Method**: NetworkX simple cycle detection over the local module dependency subgraph (`graph.circular_dependencies`).
- **Participating Elements**: Ordered list of module IDs forming the cycle.
- **Remediation**: Break the cycle by extracting shared types/interfaces to a common leaf module or adopting dependency injection.

### 5.2 `ARC-002`: Excessive Fan-Out Coupling
- **Evidence Type**: `HEURISTIC`
- **Severity**: `MEDIUM` | **Confidence**: `HIGH`
- **Threshold**: Outgoing dependencies `fan_out > 10` (configurable).
- **Rationale**: High efferent coupling increases fragility; a module that depends on many others is sensitive to upstream breaking changes.
- **Remediation**: Apply the Facade pattern or decompose the module into smaller single-responsibility components.

### 5.3 `ARC-003`: God Module Structural Smell
- **Evidence Type**: `HEURISTIC`
- **Severity**: `HIGH` | **Confidence**: `MEDIUM`
- **Threshold**: 
  - Condition 1: `LOC > 500 AND fan_out > 8 AND fan_in > 5`
  - Condition 2: `LOC > 800 AND fan_out > 10` (configurable via `--god-module-loc`).
- **Rationale**: A heuristic structural architecture smell based on LOC and coupling metrics indicating concentrated systemic complexity and high change friction.
- **Evidence Schema**: `module`, `loc`, `fan_in`, `fan_out`, `thresholds`, `matched_condition`.
- **Heuristic Disclaimer**: 
  > [!NOTE]
  > ARC-003 is explicitly defined and evaluated as a **heuristic structural architecture smell based on LOC and coupling metrics**. It indicates architectural coupling concentration and maintenance risk; it is **never** described as semantic proof of a design flaw.
- **Remediation**: Decompose module according to the Single Responsibility Principle into cohesive sub-domains.

### 5.4 `ARC-004`: Deep Dependency Chain
- **Evidence Type**: `HEURISTIC`
- **Severity**: `LOW` | **Confidence**: `MEDIUM`
- **Threshold**: Transitive chain depth `depth > 5` hops (configurable).
- **Detection Method**: Strongly connected components (SCCs) are condensed into a DAG via `nx.condensation()`, and longest paths are evaluated via `nx.dag_longest_path()`.
- **Rationale**: Excessive layering (> 5 hops) increases structural rigidity and complicates reasoning about cross-layer changes.
- **Evidence Schema**: `depth`, `threshold`, `longest_path`, `chain`.
- **Remediation**: Flatten hierarchy through direct dependency inversion or modular boundary reorganization.

### 5.5 `ARC-005`: Layer Boundary Inversion
- **Evidence Type**: `HEURISTIC`
- **Severity**: `HIGH` | **Confidence**: `MEDIUM`
- **Detection Method**: Subsystem directory structures are classified into canonical architectural tiers (`PRESENTATION`, `APPLICATION`, `DOMAIN`, `INFRASTRUCTURE`, `UTILITY`). Prohibited dependency flows (e.g. `INFRASTRUCTURE -> PRESENTATION`, `DOMAIN -> INFRASTRUCTURE`, `DOMAIN -> PRESENTATION`, `APPLICATION -> PRESENTATION`) are flagged.
- **Rationale**: Clean Architecture and hexagonal architecture require dependencies to point toward higher-stability abstract business logic. Upward dependencies create tight coupling between core domains and volatile presentation/infrastructure adapters.
- **Evidence Schema**: `source_component`, `source_tier`, `target_component`, `target_tier`, `prohibited_rule`, `violating_targets`, `violating_imports_count`.
- **Remediation**: Invert the dependency using DIP: define abstract interfaces in the core/domain layer and implement them in the infrastructure layer.

### 5.6 `ARC-006`: Component Circular Dependency Group
- **Evidence Type**: `DETERMINISTIC`
- **Severity**: `HIGH` | **Confidence**: `HIGH`
- **Detection Method**: Aggregates file-level dependencies into package/subsystem components (depth collapsed) and computes Strongly Connected Components (SCC) using Tarjan's/NetworkX algorithm.
- **Rationale**: Subsystems with mutual cyclic dependencies cannot be deployed, tested, or refactored independently, turning independent components into a distributed monolith.
- **Evidence Schema**: `scc_components`, `cycle_components`, `component_count`, `participating_edges`.
- **Deterministic ID**: Derived deterministically via `UUIDv5(namespace, "ARC-006|" + canonical_sorted_components)`.
- **Remediation**: Extract common types/interfaces into an independent leaf component or introduce an event-driven pub/sub mechanism.

### 5.7 `ARC-007`: Stable Dependencies Principle (SDP) Violation
- **Evidence Type**: `HEURISTIC`
- **Severity**: `MEDIUM` | **Confidence**: `MEDIUM`
- **Detection Method**: Evaluates Robert C. Martin package coupling metrics: Afferent Coupling ($C_a$), Efferent Coupling ($C_e$), and Instability ($I = C_e / (C_a + C_e)$). Detects dependencies where a stable component ($I \le 0.30, C_a \ge 2$) directly depends on an unstable component ($I \ge 0.70$).
- **Rationale**: A stable component should not depend on a volatile component, as volatile changes force frequent maintenance on stable dependents.
- **Evidence Schema**: `source_component`, `target_component`, `source_instability`, `target_instability`, `source_ca`, `target_ce`, `thresholds`.
- **Remediation**: Make the target component more stable or introduce an abstract interface in the stable component.

### 5.8 `ARC-008`: Potentially Orphaned Export
- **Evidence Type**: `HEURISTIC`
- **Confidence**: `MEDIUM` | **Severity**: `LOW`
- **Detection Method**: Conservative static scanning identifying exported functions, classes, and types that have zero internal callers or import references anywhere in the repository. Ignores entry points (`main.py`, `app.py`, `index.ts`, `setup.py`), whole-module imports (`import x`), and re-exports.
- **Rationale**: Dead or unused public exports accumulate dead code and unnecessarily expand the perceived public API surface.
- **Evidence Schema**: `symbol`, `symbol_name`, `file_path`, `is_default`, `scope`.
- **Remediation**: Remove or deprecate unused symbols, or remove the export statement if only used locally.

### 5.9 `ARC-009`: High-Centrality Architectural Bottleneck / Mediation Hotspot
- **Evidence Type**: `HEURISTIC`
- **Severity**: `MEDIUM` | **Confidence**: `HIGH`
- **Detection Method**: Brandes algorithm calculating betweenness centrality over the repository-local directed `ComponentGraph`. Flags components with betweenness centrality $\ge 0.30$ in codebases with $\ge 5$ components and $\ge 2$ internal source files.
- **Rationale**: Components on a disproportionately high volume of shortest dependency paths become architectural choke points, coupling hotspots, and single points of maintenance failure.
- **Evidence Schema**: `component`, `betweenness_centrality`, `in_degree_centrality`, `out_degree_centrality`, `total_components`, `total_edges`, `threshold`.
- **Remediation**: Decompose the mediation hotspot into focused sub-components or introduce decoupled event-driven communication.

---

## 6. Deterministic Finding Deduplication

To avoid alert fatigue and redundant findings, the static `RuleEngine` automatically applies deterministic deduplication before emitting results:
- **Deduplication Identity Key**: `(rule_id, file_path, line_start, col_start, normalized_evidence)`
- Distinct findings occurring on the same line (e.g. multiple variable assignments or distinct column positions) are preserved.
- Findings on the same coordinate with different structured evidence are preserved.
- Output retains canonical deterministic ordering: `file_path -> line_start -> col_start -> rule_id`.

---

## 7. Static Analysis Guarantees & Non-Claims

To preserve engineering defensibility, CodeSentinel makes explicit commitments regarding static analysis bounds:
- **No Claims of Complete Semantic Analysis**: Tree-sitter and AST visitors extract syntactic structures and direct references; whole-program abstract interpretation and type-flow solving across dynamically dispatched types are not performed.
- **No Claims of Complete Dataflow Proof**: Dynamic taint propagation across network boundaries, asynchronous message queues, or persistent database state is out of scope for the static engine.
- **No Claims of Zero False Positives**: Static patterns serve as rigorous candidate indicators; edge cases in dynamic metaprogramming may warrant developer review.
- **No Claims of Guaranteed Vulnerability or Exploitability**: Flagged issues indicate static patterns matching recognized weakness definitions (CWE); runtime exploitability depends on network topology, environmental controls, and deployment architecture.
- **No Claims of Complete Vulnerability Detection**: CodeSentinel enforces a well-defined catalog of 27 specific rules (10 Python security, 8 JS/TS security, 9 Architecture rules); absence of findings does not certify an application as defect-free.


