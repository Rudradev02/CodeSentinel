# PHASE 24 IMPLEMENTATION PLAN — Policy-Aware Security Verification, Framework Coverage Hardening & Incremental Security Intelligence

## 1. Executive Summary

Phase 24 evolves CodeSentinel from static detection with attached policy metadata into a **rigorous policy-aware security verification engine**. In Phase 23, CodeSentinel introduced declarative security policies, trust boundaries, discrete authentication/authorization states, and framework model adapters. However, policy evaluation was performed primarily at finding emission time using initial property states, framework detection was partially decoupled from framework model adapters (e.g. Express was modeled in adapters but absent from repository detection), and authorization evidence was bounded strictly to immediate function decorators without interprocedural propagation.

Phase 24 establishes an **evidence-based proof obligation model** that unifies:
1. **Trust Boundary Semantics**: Modeling entrypoints and untrusted source vectors across frameworks.
2. **Policy Proof Obligations**: Decomposing high-level security invariants into formal, verifiable obligations (`REQUIRES_AUTHENTICATION`, `REQUIRES_AUTHORIZATION`, `REQUIRES_PROPERTY`, `REQUIRES_VALIDATION`, `REQUIRES_PARAMETERIZATION`).
3. **Authentication vs. Authorization Separation**: Enforcing that authentication never implies authorization, separating permission/role checks from identity checks, and propagating authorization dominance along call graph contracts.
4. **Validation & Property Provenance**: Tracking fine-grained properties (`SQL_SAFE`, `COMMAND_SAFE`, `HTML_SAFE`, `PATH_SAFE`, `URL_SAFE`, `VALIDATED_TYPE`, `VALIDATED_FORMAT`) across CFG branches with conservative lattice joins where `UNKNOWN` is strictly preserved.
5. **Framework Coverage Hardening**: Synchronizing framework detection (`FrameworkDetector`) with model adapters (`Flask`, `Django`, `Express`, `React`), exposing formal capability matrices, and supporting framework version constraints.
6. **Incremental Cache Isolation**: Introducing fine-grained `policy_hash` and `framework_model_hash` into `ConfigFingerprint` to prevent over-invalidation of parsing (L2), dependency (L3), CFG (L4), and call graph (L6) caches during policy-only changes.
7. **Developer-Facing Policy Explanation**: Surfacing structured verification traces in CLI, API, SARIF v2.1.0, and the frontend finding drawer, distinguishing `PROVEN_SAFE`, `PROVEN_VIOLATION`, and `UNKNOWN`.

All analysis remains **100% offline, deterministic, zero-AI in `analyzer/`, and database-migration free**.

---

## 2. Repository Audit

A comprehensive inspection of the current CodeSentinel codebase reveals the following ground truth:

### 2.1 Test Suite Baseline
- **Total Tests Collected**: 725 tests across `analyzer/tests/` (612 tests) and `backend/tests/` (113 tests).
- **Execution Status**: **724 passed, 1 skipped** (`test_git_sparse_checkout` in `test_phase10_repository_isolation.py`), **0 failures**.
- **Phase 23 Dedicated Tests**: 35 tests across 8 test suites:
  - `analyzer/tests/test_phase23_boundaries.py` (5 tests)
  - `analyzer/tests/test_phase23_authentication.py` (5 tests)
  - `analyzer/tests/test_phase23_authorization.py` (4 tests)
  - `analyzer/tests/test_phase23_policies.py` (6 tests)
  - `analyzer/tests/test_phase23_sanitizer_compatibility.py` (4 tests)
  - `analyzer/tests/test_phase23_security_properties.py` (5 tests)
  - `analyzer/tests/test_phase23_integration.py` (3 tests)
  - `backend/tests/test_phase23_api_backward_compat.py` (3 tests)

### 2.2 Active Rule Registry (`analyzer/rules/registry.py`)
- Exactly **31 active rules** are registered in `RuleRegistry`:
  - **Architecture (9 rules)**: `ARC-001` through `ARC-009`.
  - **JavaScript Security (10 rules)**: `SEC-JS-001` through `SEC-JS-010`.
  - **Python Security (12 rules)**: `SEC-PY-001` through `SEC-PY-012`.
- Every rule ID referenced by Phase 23 policies exists and is fully implemented:
  - `SEC-PY-005` (Raw SQL query string construction)
  - `SEC-PY-009` (Flask SQL injection via data-flow)
  - `SEC-PY-011` (Interprocedural SQL injection)
  - `SEC-PY-003` (Unsafe subprocess execution shell=True)
  - `SEC-PY-010` (Command injection via data-flow)
  - `SEC-PY-012` (Interprocedural command injection)
  - `SEC-JS-003` (React dangerouslySetInnerHTML)
  - `SEC-JS-007` (DOM-based XSS via data-flow)
  - `SEC-JS-009` (Interprocedural DOM XSS)
  - `SEC-PY-004` (Dangerous dynamic code execution eval/exec)
  - `SEC-JS-008` (Dynamic code execution via data-flow)
  - `SEC-PY-008` (Disabled CSRF protection via @csrf_exempt)

### 2.3 Incremental Cache Architecture
- **Persistent Cache Layers**:
  - L1: File metadata & hash
  - L2: AST / normalized `ParsedFile`
  - L3: Dependency graph & module resolution
  - L4: CFG & guard conditions
  - L5: Intraprocedural dataflow & taint
  - L6: Interprocedural call graph
  - L7: Function contracts & summaries
  - L8: Contract composition graph
  - L9: Rule findings & security evidence chains
- **Current Fingerprinting (`analyzer/incremental/config_fingerprint.py`)**:
  - Computes `parsing_hash`, `dependency_hash`, `cfg_dataflow_hash`, `callgraph_hash`, `contract_hash`, `composition_hash`, `rules_hash`, `reporting_hash`, and `global_hash`.
  - Phase 23 configuration fields (`enable_boundary_detection`, `enable_policy_engine`, `policy_mode`) are currently packed inside `rules_hash` rather than having dedicated policy/framework cache scopes.

---

## 3. Phase 23 Verification

Verification of the active repository against Phase 23 specifications confirmed:
1. **Trust Boundary Models** (`analyzer/models/boundary.py`): Strongly-typed `TrustBoundaryType`, `AuthenticationState`, `AuthorizationState`, and `TrustBoundaryEvidence` exist, are frozen, and validate correctly.
2. **Security Property Lattice** (`analyzer/dataflow/properties.py`): `SecurityProperty` and `SecurityPropertyState` implement immutable operations (`with_property`, `without_property`, `join`). Conservative join ensures `UNKNOWN` persists and `UNTRUSTED` is never dropped if either branch is untrusted.
3. **Framework Adapters** (`analyzer/frameworks/`): `FlaskAdapter`, `DjangoAdapter`, `ExpressAdapter`, and `ReactAdapter` exist and inherit from `BaseFrameworkAdapter`.
4. **Policy Engine** (`analyzer/rules/policy.py`): Canonical policies `POL-SQL-01`, `POL-CMD-01`, `POL-DOM-01`, `POL-EVAL-01`, and `POL-AUTHZ-01` are registered and evaluate correctly.
5. **Evidence Chain** (`analyzer/models/evidence.py`): `SecurityEvidenceChain` was extended additively with `trust_boundary`, `authentication`, `authorization`, `policy_evaluation`, and `security_properties`.
6. **SARIF Reporting** (`analyzer/reporting/sarif.py`): Outputs `policyId`, `policyResult`, `trustBoundary`, and `framework` properties in compliant OASIS SARIF v2.1.0 format.

---

## 4. Discrepancies Found

Audit of the active implementation revealed four concrete discrepancies:

| ID | Component | Walkthrough Claim | Actual Implementation Reality | Phase 24 Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **DISC-01** | `analyzer/detection/frameworks.py` | Full multi-framework detection for Flask, Django, Express, React | `FrameworkDetector.detect()` only inspects Python manifests and `package.json` for `django`, `flask`, and `react`. It has **no Express detection logic** (`"express"` in `dependencies` is never checked). | Add Express manifest & import pattern detection to `FrameworkDetector` so `detected_frameworks` contains `"express"` when present. |
| **DISC-02** | `analyzer/config/settings.py` | Phase 23 configuration fields declared on `AnalysisConfig` | Fields (`enable_boundary_detection`, `max_security_boundaries`, `enable_policy_engine`, `max_policy_paths`, `policy_mode`) are passed dynamically via kwargs and retrieved via `getattr(self.config, ...)`. They are not explicitly typed on `AnalysisConfig`. | Explicitly declare Phase 23/24 fields on `AnalysisConfig` with Pydantic field validators and defaults. |
| **DISC-03** | `analyzer/rules/engine.py` | Policy evaluation uses full dataflow path property state | `RuleEngine.analyze_security` evaluates policies using a blank `prop_state = SecurityPropertyState()`, only checking single sanitizer IDs from finding evidence. Property accumulation along CFG/taint paths is not dynamically fed into policy evaluation. | Bridge dataflow path states and interprocedural taint propagation steps into `SecurityPropertyState` before policy evaluation. |
| **DISC-04** | `analyzer/incremental/config_fingerprint.py` | Independent policy invalidation | Policy settings are packed into `rules_hash`. Changing a policy invalidates all rule findings rather than isolating policy evaluation recomputation. | Introduce dedicated `policy_hash` and `framework_model_hash` into `ConfigFingerprint` and cache layer invalidation. |

---

## 5. Current Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CodeSentinel Pipeline                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │ Framework Ingestion   │             │ Normalized Parsers    │
        │ FrameworkDetector     │             │ (Python AST / TS-CST) │
        └───────────────────────┘             └───────────────────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Call Graph & Contract Composition │
                     │ (Phase 15–20 Interprocedural)     │
                     └───────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │ Framework Adapters    │             │ Security Rules Engine │
        │ TrustBoundaryEvidence │             │ Taint Paths & Sinks   │
        └───────────────────────┘             └───────────────────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Phase 23 Policy Engine            │
                     │ (POL-SQL-01, POL-CMD-01, etc.)    │
                     └───────────────────────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Canonical Finding & EvidenceChain │
                     │ SARIF 2.1.0 / Backend DTOs / CLI  │
                     └───────────────────────────────────┘
```

---

## 6. Phase 24 Goals

Phase 24 establishes an **end-to-end policy-aware security verification engine**:
1. **Policy Proof Obligations**: Formalize invariants as explicit obligations (`REQUIRES_AUTHENTICATION`, `REQUIRES_AUTHORIZATION`, `REQUIRES_PROPERTY`, `REQUIRES_VALIDATION`, `REQUIRES_PARAMETERIZATION`) evaluated against path evidence.
2. **Interprocedural Authorization Dominance**: Propagate verified authorization checks along call-graph edges through function contracts and cross-module summaries.
3. **Granular Property Compatibility Matrix**: Enforce strict context boundaries preventing cross-sink sanitizer laundering (`HTML_SAFE` cannot satisfy SQL; `COMMAND_SAFE` cannot satisfy DOM).
4. **Validation Provenance**: Distinguish structural type casts (`int()`, `float()`), regex whitelists, and domain validations from cosmetic variable naming.
5. **Synchronized Framework Model Registry**: Elevate framework adapters to declare explicit capability matrices, detection tokens, version ranges, and trust boundary extractors.
6. **Scoped Incremental Invalidation**: Isolate policy and framework changes so L2 (parsing), L3 (dependency), and L4 (CFG) caches are preserved.
7. **Equivalence & Determinism**: Guarantee identical canonical semantic projections between clean full runs and incremental runs across all policy verification states.
8. **Explainable Diagnostics**: Deliver full-fidelity verification traces in CLI, SARIF, backend DTOs, and frontend UI, clearly distinguishing `PROVEN_SAFE`, `PROVEN_VIOLATION`, and `UNKNOWN`.

---

## 7. Non-Goals

The following areas are strictly outside the scope of Phase 24:
- **No Dynamic Code Execution**: No executing target repository code, invoking Python/Node runtimes, or dynamic instrumentation.
- **No Network Access or Package Installation**: Static analysis must remain 100% offline.
- **No AI Modification of Security Truth**: AI providers remain strictly advisory for developer triage; they cannot modify policy results, override severity, or convert `UNKNOWN` to `SAFE`.
- **No Database Migrations**: Persistence schemas already store finding evidence as flexible JSON; no PostgreSQL schema migrations are permitted.
- **No Parallel Engines**: Do not create a second taint propagator, a second contract system, or a second rule registry. All verification must build upon existing Phase 1–23 components.
- **No SMT / Theorem Prover Heavyweights**: All proof obligations must be solved deterministically using bounded abstract interpretation, lattice meets/joins, and CFG reachability.

---

## 8. Architecture Changes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Phase 24 Verification Pipeline                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
     ┌─────────────────────────────────┴─────────────────────────────────┐
     ▼                                                                   ▼
┌─────────────────────────┐                                 ┌─────────────────────────┐
│ Framework Model Registry│                                 │ Policy Proof Obligation │
│ • Capability Matrix     │                                 │ Engine                  │
│ • Flask/Django/Express/ │                                 │ • Decomposes Invariants │
│   React Adapters        │                                 │ • Checks Path Evidence  │
└─────────────────────────┘                                 └─────────────────────────┘
     │                                                                   │
     └─────────────────────────────────┬─────────────────────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Call Graph Contract Propagation   │
                     │ • Authz Dominance across modules  │
                     │ • Validation Provenance Tracking  │
                     │ • Property Lattice Meet/Join      │
                     └───────────────────────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Obligation Evaluation Matrix      │
                     │ PROVEN_SAFE                       │
                     │ PROVEN_VIOLATION                  │
                     │ UNKNOWN (Strict Preservation)     │
                     └───────────────────────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Enriched SecurityEvidenceChain    │
                     │ (proof_obligations, audit_trail)  │
                     └───────────────────────────────────┘
```

---

## 9. Policy Proof Obligations

### 9.1 Obligation Types & Data Model
Proof obligations represent concrete predicates that an execution trace must satisfy before untrusted input can reach a sensitive operation without raising a finding:

```python
class ObligationKind(str, Enum):
    REQUIRES_AUTHENTICATION = "REQUIRES_AUTHENTICATION"
    REQUIRES_AUTHORIZATION = "REQUIRES_AUTHORIZATION"
    REQUIRES_PROPERTY = "REQUIRES_PROPERTY"
    REQUIRES_VALIDATION = "REQUIRES_VALIDATION"
    REQUIRES_SANITIZER = "REQUIRES_SANITIZER"
    REQUIRES_PARAMETERIZATION = "REQUIRES_PARAMETERIZATION"


class ObligationEvaluationState(str, Enum):
    PROVEN_SAFE = "PROVEN_SAFE"
    PROVEN_VIOLATION = "PROVEN_VIOLATION"
    UNKNOWN = "UNKNOWN"


class PolicyProofObligation(BaseModel):
    model_config = ConfigDict(frozen=True)

    obligation_id: str
    policy_id: str
    kind: ObligationKind
    target_sink_category: SinkCategory
    required_property: Optional[SecurityProperty] = None
    required_permission: Optional[str] = None
    target_expression: str
    file_path: str
    line: int
    state: ObligationEvaluationState = ObligationEvaluationState.UNKNOWN
    evidence_details: str = ""
    unknown_reason: Optional[str] = None
```

### 9.2 Evaluation Invariants
- **No Conversion of Absence to Proof**: If authorization cannot be proven to dominate the sink path, state is `UNKNOWN` (or `PROVEN_VIOLATION` if policy mandates strict enforcement).
- **Additive Decomposition**: A policy may generate multiple obligations (e.g. `POL-AUTHZ-SQL-01` generates both `REQUIRES_AUTHENTICATION` and `REQUIRES_PROPERTY: SQL_SAFE`). The overall policy is satisfied iff **all** obligations evaluate to `PROVEN_SAFE`.

---

## 10. Authentication vs. Authorization

### 10.1 Strict Semantic Separation
CodeSentinel enforces that identity verification (authentication) and privilege enforcement (authorization) are fundamentally distinct:
1. **Authentication Evidence**:
   - Flask: `@login_required`, `@jwt_required()`.
   - Django: `@login_required`, `request.user.is_authenticated`.
   - Express: `passport.authenticate()`, `jwt.verify()`.
2. **Authorization Evidence**:
   - Flask: `@roles_required('admin')`, `@permission_required('delete')`.
   - Django: `@permission_required('app.perm')`, `@user_passes_test(lambda u: u.is_superuser)`.
   - Express: Role/permission middleware specifically verified in route chain.

### 10.2 Bounded Authorization Scope
Authorization states are categorized strictly by verified static evidence:
- `ROLE_VERIFIED`: Caller has an explicit role attribute verified by structural check/decorator.
- `PERMISSION_GRANTED`: Caller has an explicit named permission string checked.
- `RESOURCE_ACCESS_VERIFIED`: Parameterized check verifying caller matches resource owner.
- `UNKNOWN`: Default when no recognized structural authorization check dominates the path.

### 10.3 Interprocedural Authorization Dominance
When an entrypoint verifies authorization (e.g. `@permission_required("user.delete")` on a Django view), that authorization is captured as a **Contract Postcondition** on the view function in L7 contract generation. As the call graph propagates to `user_service.delete_user(user_id)` and `user_repo.delete(user_id)`, the call graph contract composition engine checks if all paths leading to `user_repo.delete` are dominated by the permission check.
- If **all** incoming call graph paths dominate through verified authorization: `ObligationEvaluationState.PROVEN_SAFE`.
- If **any** path bypasses authorization or enters through an untracked caller: `ObligationEvaluationState.UNKNOWN` or `PROVEN_VIOLATION`.

---

## 11. Validation & Security Properties

### 11.1 Validation Provenance
Validation evidence is classified into concrete, statically verifiable categories:
- `VALIDATED_TYPE`: Integer/float scalar conversion (`int(val)`, `float(val)`), numeric type constraints.
- `VALIDATED_FORMAT`: Regular expression match (`re.match(r'^\w+$', val)`), UUID parser (`uuid.UUID(val)`).
- `VALIDATED_RANGE`: Bounds checking (`0 <= val <= 100`).
- `VALIDATED_ENUM`: Membership in a fixed literal set/enum (`val in ALLOWED_STATUSES`).
- `UNKNOWN`: Unrecognized helper function, type annotation without runtime check, or variable name heuristics.

### 11.2 Property Compatibility Matrix

| Security Property | SQL Sink (`SQL_EXECUTE`) | Shell Sink (`COMMAND_EXECUTE`) | DOM Sink (`DOM_INJECTION`) | Code Eval (`CODE_EVAL`) | File Path (`FILE_PATH`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `SQL_SAFE` | **YES** | NO | NO | NO | NO |
| `COMMAND_SAFE` | NO | **YES** | NO | NO | NO |
| `HTML_SAFE` | NO | NO | **YES** | NO | NO |
| `URL_SAFE` | NO | NO | **YES** (href/src) | NO | NO |
| `PATH_SAFE` | NO | NO | NO | NO | **YES** |
| `VALIDATED_TYPE` | **YES** | **YES** | **YES** | **YES** | **YES** |
| `VALIDATED_FORMAT` | Conditional | Conditional | Conditional | Conditional | Conditional |
| `UNTRUSTED` | NO | NO | NO | NO | NO |
| `UNKNOWN` | NO | NO | NO | NO | NO |

Any cross-context misuse (e.g. passing `html.escape()` sanitized data to `cursor.execute()`) triggers an immediate `ObligationEvaluationState.PROVEN_VIOLATION`.

---

## 12. Framework Capability Matrix

Framework adapters in `analyzer/frameworks/` are enhanced to declare formal capabilities:

```python
class FrameworkCapability(BaseModel):
    model_config = ConfigDict(frozen=True)

    framework_id: str
    display_name: str
    supports_route_extraction: bool
    supports_path_parameters: bool
    supports_request_body: bool
    supports_authentication_extraction: bool
    supports_authorization_extraction: bool
    supported_versions: str = ">=1.0.0"
    detection_manifest_tokens: list[str]
    detection_source_tokens: list[str]
```

### Framework Capability Matrix:

| Framework | Detection Ingestion | Route Decorators | Path Params | Request Data | Auth Detection | Authz Detection | Client DOM Sinks |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Flask** | Manifest + Source | `@app.route`, Blueprints | `<converter:param>` | `request.args`, `.json`, `.form` | `@login_required`, `@jwt_required` | Custom decorators | N/A |
| **Django** | Manifest + Source | `urls.py` + View functions | View parameters | `request.GET`, `.POST`, `.body` | `@login_required` | `@permission_required`, `@user_passes_test` | N/A |
| **Express** | Manifest + Source (`package.json`) | `app.get`, `router.post` | `:param` | `req.query`, `req.body`, `req.params` | `passport`, JWT middleware | Custom middleware | N/A |
| **React** | Manifest + Source | Component trees | `useParams()` | `useSearchParams()`, props | Client session hooks | Role guards in JSX | `dangerouslySetInnerHTML`, `innerHTML` |

---

## 13. Policy Registry Hardening

The `SecurityPolicyRegistry` is hardened with explicit query and conflict detection capabilities:

### 13.1 Registered Canonical Policies
1. **`POL-SQL-01`**: SQL Query Parameterization & Numeric Type Constraints
   - Sinks: `SQL_EXECUTE`
   - Associated Rules: `SEC-PY-005`, `SEC-PY-009`, `SEC-PY-011`
   - Required Obligations: `REQUIRES_PROPERTY(SQL_SAFE)` OR `REQUIRES_VALIDATION(VALIDATED_TYPE)`
2. **`POL-CMD-01`**: OS Command Shell Argument Escaping
   - Sinks: `COMMAND_EXECUTE`
   - Associated Rules: `SEC-PY-003`, `SEC-PY-010`, `SEC-PY-012`
   - Required Obligations: `REQUIRES_PROPERTY(COMMAND_SAFE)`
3. **`POL-DOM-01`**: DOM & HTML XSS Sanitization
   - Sinks: `DOM_INJECTION`
   - Associated Rules: `SEC-JS-003`, `SEC-JS-007`, `SEC-JS-009`
   - Required Obligations: `REQUIRES_PROPERTY(HTML_SAFE)`
4. **`POL-EVAL-01`**: Dynamic Code Execution Invariant
   - Sinks: `CODE_EVAL`
   - Associated Rules: `SEC-PY-004`, `SEC-JS-008`, `SEC-JS-010`
   - Required Obligations: `REQUIRES_VALIDATION(VALIDATED_TYPE)`
5. **`POL-AUTHZ-01`**: Privileged Operation Authorization Enforcement
   - Sinks: `CODE_EVAL`, `COMMAND_EXECUTE`, `SQL_EXECUTE` (under privileged operations)
   - Associated Rules: `SEC-PY-008`
   - Required Obligations: `REQUIRES_AUTHENTICATION`, `REQUIRES_AUTHORIZATION`

### 13.2 Policy Conflict Resolution
When two policies apply to the same sink (e.g. general SQL policy vs. an anonymous-access read policy):
- **Precedence**: Specific policy overrides generic policy only if explicitly configured via `policy_precedence` in configuration.
- **Safety Fallback**: If two policies have conflicting requirements and no explicit precedence exists, the evaluation defaults to `ObligationEvaluationState.UNKNOWN` with an explicit reason logged: `"Conflicting policy requirements detected without explicit precedence"`.

---

## 14. Path, Loop & Exception Semantics

### 14.1 Path Sensitivity
Policy obligations are evaluated with full awareness of Phase 18 CFG branch conditions:
```python
if is_authorized(user):
    delete_record(user_id)  # Path condition: is_authorized == True -> SATISFIED
else:
    delete_record(user_id)  # Path condition: is_authorized == False -> VIOLATION
```
The obligation state is path-bound; findings are emitted only for paths where the obligation fails.

### 14.2 Loop Semantics
Loops are explored up to the established `max_branch_depth` (default: 6) and `max_alias_iterations` (default: 5). If loop invariants cannot be proven within budget, the obligation state degrades safely to `UNKNOWN` rather than falsely assuming safety.

### 14.3 Exception Semantics
In `try...except...finally` blocks:
- Sanitizers or authorization checks that occur *after* an operation in a `try` block do not protect the operation.
- In `except` blocks, taint is preserved if handled data is re-used in error logging or database queries.
- `finally` blocks execute on all terminating paths, but obligations cannot assume normal completion of statements inside the `try` block.

---

## 15. Finding Integration & Health Scoring

### 15.1 Deduplication Guarantee
Phase 24 findings maintain strict identity compatibility:
$$\text{Finding ID} = \text{UUIDv5}(\text{NAMESPACE\_URL}, f"{rule\_id}:{normalized\_path}:{line\_start}:{column\_start}") $$
Policy evaluation **enriches** existing finding evidence bags (`finding.evidence["policy_evaluation"]`, `finding.evidence["proof_obligations"]`) rather than spawning duplicate findings.

### 15.2 Health Score Consistency
- In `ENFORCE` mode, findings where all policy obligations evaluate to `PROVEN_SAFE` are suppressed. Suppressed findings do **not** contribute to deduction counts in `HealthScoreCalculator`.
- In `ADVISORY` mode, findings are preserved with policy evaluation metadata, and health deductions follow standard rule severity without double-counting.

---

## 16. Incremental Cache Changes

### 16.1 Dedicated Fingerprint Scopes
Extend `ConfigFingerprint` in `analyzer/incremental/models.py` and `analyzer/incremental/config_fingerprint.py`:
- `policy_hash`: SHA-256 digest of active policies, required properties, and enforcement mode.
- `framework_model_hash`: SHA-256 digest of framework capabilities, registered adapter versions, and boundary tokens.

### 16.2 Invalidation Matrix

| Cache Layer | Source File Change | Dependency Graph Change | Policy Configuration Change | Framework Model Change | Rule Definition Change |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **L1 File Metadata** | Recomputed | Recomputed | Reused | Reused | Reused |
| **L2 AST / Parse** | Recomputed | Reused | **Reused** | **Reused** | **Reused** |
| **L3 Dependency Graph** | Recomputed | Recomputed | **Reused** | **Reused** | **Reused** |
| **L4 CFG / Guards** | Recomputed | Reused | **Reused** | **Reused** | **Reused** |
| **L5 Dataflow / Taint** | Recomputed | Reused | **Reused** | Recomputed | **Reused** |
| **L6 Call Graph** | Recomputed | Recomputed | **Reused** | **Reused** | **Reused** |
| **L7 Contracts** | Recomputed | Recomputed | Recomputed | Recomputed | **Reused** |
| **L8 Composition** | Recomputed | Recomputed | Recomputed | Recomputed | **Reused** |
| **L9 Findings / Evidence** | Recomputed | Recomputed | Recomputed | Recomputed | Recomputed |

---

## 17. Equivalence Verification

The `EquivalenceChecker` (`analyzer/incremental/equivalence.py`) is extended to project and verify:
1. `finding_ids`: Exact match of finding UUIDs.
2. `policy_evaluation_results`: Exact match of policy IDs, evaluation states (`PROVEN_SAFE`, `PROVEN_VIOLATION`, `UNKNOWN`), and missing properties.
3. `trust_boundary_evidence`: Exact match of boundary types, HTTP methods, and parameter names.
4. `health_scores`: Exact match of overall health score, sub-scores, and letter grades.

Non-semantic metadata (timestamps, elapsed execution times, cache hit counts) are strictly excluded from the canonical equivalence projection.

---

## 18. CLI Changes

Update `analyzer/cli/main.py`:
- Explicitly register `--policy-mode` (`ENFORCE`, `ADVISORY`, `DISABLED`).
- Add `--verify-policy <POLICY_ID>` to run policy verification targeted to specific invariant IDs.
- Update `--explain-policy` to print the complete proof obligation verification table in terminal output:
  ```text
  [POLICY EVALUATION] POL-SQL-01: SQL Query Parameterization & Safety
  Target Sink: SQL_EXECUTE at backend/app.py:15
  Boundary:    HTTP_REQUEST_PARAM 'user_id' via Flask route /api/users/<user_id>
  Auth State:  AUTHENTICATED (Flask @login_required)
  Authz State: UNKNOWN (No permission check dominating call)
  Obligations:
    [VIOLATED] REQUIRES_PROPERTY: SQL_SAFE (Missing: parameterization or numeric cast)
  Result:      PROVEN_VIOLATION
  ```

---

## 19. API Changes

Update FastAPI schemas in `backend/app/schemas/analysis.py`:
- Extend `FindingDTO.dataflow_evidence` to support `proof_obligations`:
  ```python
  class ProofObligationDTO(BaseModel):
      obligation_id: str
      policy_id: str
      kind: str
      state: str
      target_expression: str
      evidence_details: str
      unknown_reason: Optional[str] = None
  ```
- All changes are strictly backward compatible with existing clients. Historical snapshots deserialize with `proof_obligations = []`.

---

## 20. Celery / Async Analysis

Ensure asynchronous analysis jobs preserve policy configuration:
- In `backend/app/services/job_service.py` and `backend/app/workers/analysis_tasks.py`, `analysis_config.policy_mode` is serialized into job parameters.
- Cooperative cancellation tokens are checked between proof obligation evaluations.
- SSE job progress events stream the policy verification stage (`"STAGE_POLICY_VERIFICATION"` at 92% progress).

---

## 21. Frontend Changes

1. **`FindingDetailDrawer.tsx`**: Add a dedicated **Policy Verification & Proof Obligations** section.
2. **Visual States**:
   - `PROVEN_SAFE`: Green badge with shield check icon.
   - `PROVEN_VIOLATION`: Rose/red badge with alert octagon icon.
   - `UNKNOWN`: Amber/slate badge with help circle icon and prominent text: *"Uncertainty: Analyzer could not deterministically prove authorization or sanitization"*. **Never display UNKNOWN as safe.**
3. **Trace Timeline**: Render the 9-stage verification progression from Trust Boundary to Sensitive Sink.

---

## 22. SARIF Changes

Update `analyzer/reporting/sarif.py` to populate SARIF v2.1.0 property bags on results:
```json
{
  "properties": {
    "policyId": "POL-SQL-01",
    "policyResult": "PROVEN_VIOLATION",
    "trustBoundary": "HTTP_REQUEST_PARAM",
    "framework": "FLASK",
    "authenticationState": "AUTHENTICATED",
    "authorizationState": "UNKNOWN",
    "unknownReason": "No dominating permission check found on path"
  }
}
```

---

## 23. Security Hardening

- **No Remote Imports**: Custom validators or authorizers in configuration are parsed as static symbol strings only; no dynamic importing or reflection on target repository files.
- **Resource Exhaustion Guard**: Limit max policy obligations evaluated per finding to 32 and max boundary extractions per file to 500.
- **Path Traversal Shield**: Reject any repository-relative file path in boundary evidence that attempts to escape workspace root (`../`).

---

## 24. Performance Limits

| Metric / Resource | Budget / Limit | Rationale |
| :--- | :--- | :--- |
| Max Policy Proof Obligations per Finding | 32 | Prevents combinatorial explosion on highly complex sinks |
| Max Policy Evaluation Depth | 10 | Matches call graph and contract propagation depth |
| Max Framework Boundary Extractions per File | 500 | Protects against generated files with thousands of routes |
| Max Total Policy Invariants in Registry | 256 | Ensures constant-time policy dispatch |
| Incremental Policy Invalidation Time | < 50ms | Avoids pipeline stalls when only policy flags change |

---

## 25. Test Plan

Phase 24 implementation will introduce dedicated unit, integration, and regression suites:

1. **`test_phase24_proof_obligations.py`**:
   - Obligation creation, decomposition of policies, and evaluation outcomes (`PROVEN_SAFE`, `PROVEN_VIOLATION`, `UNKNOWN`).
2. **`test_phase24_auth_authz_separation.py`**:
   - Verifying `@login_required` does NOT grant authorization; verifying `@permission_required` satisfies authorization obligation.
3. **`test_phase24_interprocedural_authz.py`**:
   - Dominance propagation from route handler through service layer to database sink.
4. **`test_phase24_validation_provenance.py`**:
   - Integer/float casts, regex checks, and rejection of naming heuristics (`validate_admin()`).
5. **`test_phase24_sanitizer_matrix.py`**:
   - Comprehensive cross-context sanitizer compatibility matrix testing.
6. **`test_phase24_express_detection.py`**:
   - Repository-level Express framework detection and end-to-end boundary extraction.
7. **`test_phase24_incremental_policy_invalidation.py`**:
   - Policy-only configuration change scenario verifying L2/L3/L4 cache hit and selective L9 recomputation.
8. **`test_phase24_full_incremental_equivalence.py`**:
   - Clean full analysis vs. incremental analysis comparing canonical semantic projections.
9. **`test_phase24_unknown_preservation.py`**:
   - Proving that unresolvable functions, dynamic dispatches, and budget truncations strictly yield `UNKNOWN`.
10. **`backend/tests/test_phase24_api_backward_compat.py`**:
    - Serializing/deserializing proof obligations in `FindingDTO` and asserting zero backend imports in analyzer.

---

## 26. End-to-End Scenarios

- **Scenario A (Authenticated but Unauthorized)**: Route has `@login_required` but calls privileged `delete_all()` without permission check. Expect: `AUTHENTICATED`, `UNKNOWN` authorization, policy violation finding emitted.
- **Scenario B (Authorized Sensitive Operation)**: Route has `@permission_required('admin.delete')` dominating all paths to repository sink. Expect: `AUTHORIZED`, `PROVEN_SAFE`, finding suppressed in `ENFORCE` mode.
- **Scenario C (Interprocedural Dominance Bypass)**: Service function called by two routes: one with permission check, one public. Expect: `UNKNOWN` authorization on public path, finding emitted.
- **Scenario D (Validation + SQL)**: Request param passed through `int()` before SQL query. Expect: `VALIDATED_TYPE`, `PROVEN_SAFE`.
- **Scenario E (Cross-Context Sanitizer Misuse)**: Request param passed through `html.escape()` before SQL query. Expect: `HTML_SAFE` but `NOT SQL_SAFE`, `PROVEN_VIOLATION`.
- **Scenario F (Express Route End-to-End)**: Express app with `app.post('/api/item/:id')` and unescaped shell execution. Expect: Framework detected as Express, boundary extracted, command injection finding flagged with policy metadata.
- **Scenario G (Policy-Only Cache Invalidation)**: Switch policy mode from `ENFORCE` to `ADVISORY`. Verify L2-L6 caches hit 100%, L9 recomputed, equivalence verified.

---

## 27. Documentation Updates

The following documentation files will be updated during Phase 24 implementation:
- `docs/SECURITY_RULES.md`: Document canonical policy obligations and the property compatibility matrix.
- `docs/API.md`: Document `ProofObligationDTO` and SARIF property additions.
- `docs/AI_PIPELINE.md`: Reaffirm the advisory-only boundary of AI enrichment.
- `docs/SARIF.md`: Document Phase 24 SARIF v2.1.0 property bag extensions.
- `README.md`: Update feature matrix to include framework-aware policy intelligence.

---

## 28. Architectural Decision Records (ADRs)

- **ADR-024-01**: *Policy Proof Obligation Decomposition Model*
- **ADR-024-02**: *Interprocedural Dominance for Static Authorization Evidence*
- **ADR-024-03**: *Strict Context-Specific Property Lattice and Anti-Laundering Invariants*
- **ADR-024-04**: *Fine-Grained Policy and Framework Cache Layer Fingerprinting*

---

## 29. Implementation Stages

| Stage | Name | Description | Output Artifacts |
| :--- | :--- | :--- | :--- |
| **Phase 24.1** | Repository & Detection Sync | Add Express detection to `FrameworkDetector`; synchronize framework metadata | `analyzer/detection/frameworks.py` |
| **Phase 24.2** | Proof Obligation Models | Define `ObligationKind`, `PolicyProofObligation`, and lattice evaluation | `analyzer/models/obligation.py` |
| **Phase 24.3** | Interprocedural Authorization | Propagate authorization dominance via call graph contracts and summaries | `analyzer/dataflow/callgraph/`, `analyzer/rules/` |
| **Phase 24.4** | Property Provenance & Validation | Implement structural type and regex validation evidence extractors | `analyzer/dataflow/properties.py` |
| **Phase 24.5** | Framework Model Hardening | Formalize `FrameworkCapability` across Flask, Django, Express, React | `analyzer/frameworks/` |
| **Phase 24.6** | Policy Registry Hardening | Implement conflict resolution and obligation generation | `analyzer/rules/policy.py` |
| **Phase 24.7** | Path-Sensitive Evaluation | Bind obligation evaluation to CFG branch feasibility and loops | `analyzer/rules/engine.py` |
| **Phase 24.8** | Config & Cache Fingerprinting | Add `policy_hash` and `framework_model_hash` to `ConfigFingerprint` | `analyzer/incremental/config_fingerprint.py` |
| **Phase 24.9** | Equivalence & Equivalence Tests | Enhance `EquivalenceChecker` with obligation projections | `analyzer/incremental/equivalence.py` |
| **Phase 24.10** | SARIF, CLI & API Updates | Surface obligations in SARIF properties, CLI tables, and backend DTOs | `analyzer/reporting/sarif.py`, `analyzer/cli/main.py`, `backend/` |
| **Phase 24.11** | Frontend Explanation UI | Render policy verification breakdown in `FindingDetailDrawer.tsx` | `frontend/src/components/findings/` |
| **Phase 24.12** | Test Suite & Full Verification | Execute complete test suite (724+ tests) with zero regressions | All test suites |

---

## 30. Completion Gates

- **Gate 1 (Regression Integrity)**: All 724 existing tests continue to pass without failure.
- **Gate 2 (Dedicated Phase 24 Tests)**: All new Phase 24 unit, integration, and equivalence tests pass.
- **Gate 3 (Boundary Independence)**: Zero backend, AI, or database imports inside `analyzer/`.
- **Gate 4 (Unknown Preservation)**: Absolute guarantee that `UNKNOWN` never transitions into `SAFE`.
- **Gate 5 (Authorization Separation)**: Authentication never satisfies an authorization obligation.
- **Gate 6 (Sanitizer Context Integrity)**: Cross-context sanitizers are rejected by sink compatibility checks.
- **Gate 7 (Incremental Equivalence)**: Full analysis and incremental re-analysis produce identical canonical semantic projections.
- **Gate 8 (Deterministic Output)**: Repeated analyses produce identical canonical outputs.

---

## 31. Risks & Mitigations

| Risk | Impact | Mitigation Strategy | Fallback Behavior |
| :--- | :--- | :--- | :--- |
| **Interprocedural path explosion in authorization dominance** | High analysis latency or timeouts | Bound authorization propagation depth to call depth budget ($\le 10$) | Degrade path state to `UNKNOWN` when budget exhausted |
| **Over-invalidation of caches on policy edits** | Degraded incremental performance | Isolate `policy_hash` to invalidate only L7-L9 caches, preserving L2-L6 | Conservative full re-analysis if fingerprint corrupted |
| **Application-specific authorization decorators** | False positives on custom auth frameworks | Support explicit static declarations in `.codesentinel.yml` | Treat unrecognized decorators as `UNKNOWN` |
| **SARIF viewer rejection of custom property bags** | Broken CI/CD uploads | Strictly nest extensions inside SARIF v2.1.0 standard `properties` dictionary | Output standard SARIF fields without custom properties |
| **Frontend UI clutter from detailed obligation trees** | Degraded developer experience | Collapsible accordion sections with summary badges (`X/Y obligations satisfied`) | Render high-level policy badge only |

---

## 32. Final Acceptance Criteria

Phase 24 will be considered complete when:
1. `docs/PHASE_24_IMPLEMENTATION_PLAN.md` has been reviewed and executed across all 12 implementation stages.
2. `FrameworkDetector` accurately detects Express repositories alongside Flask, Django, and React.
3. Every security finding evaluated under a policy contains structured `proof_obligations` with unambiguous evidence trails.
4. Authorization is proven not to conflate with authentication.
5. The incremental cache reuses L2–L6 caches during policy-only configuration changes.
6. The entire repository test suite (724 baseline + new Phase 24 tests) passes with 100% success rate.
