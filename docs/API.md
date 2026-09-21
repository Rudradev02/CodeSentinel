# CodeSentinel Local Developer API Reference (Phase 8)

> **Important Deployment Notice**:  
> The CodeSentinel Phase 8 API is designed and intended strictly for **local development and local workstation execution**.  
> The API binds by default to `127.0.0.1` and accepts local filesystem paths. It **MUST NOT** be exposed directly to the public internet or deployed as an unauthenticated multi-user public service.

---

## 1. Overview & Guarantees

CodeSentinel is an offline, deterministic static analysis engine auditing codebases for architectural smells and security vulnerabilities.

### Phase 8 Architectural Invariants
- **Localhost Developer Scope**: Operates in local workstation environments.
- **Strictly Offline & Static**: Zero runtime execution of analyzed code, zero dynamic imports, zero external network queries, zero subprocesses.
- **Purely Stateless**: Zero database connections (PostgreSQL/SQLite deferred to Phase 9), zero background queues (Celery/Redis deferred to Phase 9), zero persistent server-side analysis cache.
- **Deterministic**: Semantically identical canonical analysis results for identical repository contents and configuration.
- **Standard HTTP Error Statuses**: Uses HTTP 400, 403, 404, 422, and 500 with a structured error body.

---

## 2. Base URLs & Service Discovery

| Service | Address | Description |
| :--- | :--- | :--- |
| **Backend API** | `http://127.0.0.1:8000` | FastAPI developer service |
| **Interactive UI** | `http://localhost:5173` | React + Vite + Monaco + React Flow dashboard |
| **OpenAPI Documentation** | `http://127.0.0.1:8000/docs` | Interactive Swagger UI |
| **OpenAPI Schema** | `http://127.0.0.1:8000/openapi.json` | Raw OpenAPI 3.1 JSON schema |

---

## 3. Endpoints

### 3.1 Execute Static Analysis
`POST /api/v1/analyze`

Executes an end-to-end static audit on a local directory path synchronously in the worker thread pool.

#### Request Body (`application/json`)
```json
{
  "path": "analyzer/tests/fixtures/sample_project",
  "fail_on": "HIGH",
  "enabled_rules": ["ARC-001", "SEC-PY-001"],
  "disabled_rules": ["ARC-004"],
  "max_component_depth": 2
}
```

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `path` | `string` | **Yes** | Local directory path to analyze (absolute or relative to current working directory). |
| `fail_on` | `string` | No | Optional severity threshold: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `enabled_rules` | `list[str]` | No | Optional whitelist of rule IDs to evaluate. |
| `disabled_rules`| `list[str]` | No | Optional blacklist of rule IDs to skip. |
| `max_component_depth` | `int` | No | Maximum directory depth for subsystem component aggregation (default: 2). |

#### Response (`200 OK`)
```json
{
  "id": "7ec928f6-2fa5-4505-8977-96a6042db62b",
  "status": "COMPLETED",
  "repository_path": "E:\\AI-Workspace\\projects\\CodeSentinel\\analyzer\\tests\\fixtures\\sample_project",
  "repository_name": "sample_project",
  "summary": {
    "total_findings": 4,
    "critical": 0,
    "high": 4,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total_modules": 7,
    "circular_dependencies_count": 1,
    "total_files": 7,
    "total_loc": 68,
    "duration_seconds": 0.035
  },
  "health": {
    "overall_score": 84.7,
    "overall_grade": "B",
    "architecture_health": {
      "score": 66.0,
      "grade": "D",
      "deductions": [
        {
          "category": "ARCHITECTURE",
          "rule_id": "ARC-001",
          "points_deducted": 15.0,
          "reason": "Circular file-level dependency detected",
          "finding_id": null,
          "item_count": 1
        }
      ]
    },
    "security_posture": {
      "score": 100.0,
      "grade": "A",
      "deductions": []
    },
    "total_deductions_count": 2,
    "summary": "Moderate structural risks detected. Architecture requires decoupling."
  },
  "findings": [
    {
      "id": "e44d326f-40e9-4468-b71a-289ec0a3bece",
      "rule_id": "ARC-001",
      "rule_name": "Circular Dependency",
      "message": "Circular dependency detected between backend/core/engine.py and backend/services/auth.py",
      "category": "ARCHITECTURE",
      "severity": "HIGH",
      "confidence": "HIGH",
      "description": "Modules participate in a circular dependency chain.",
      "remediation": "Refactor common interfaces into a shared contract module.",
      "location": {
        "file_path": "backend/core/engine.py",
        "line_start": 4,
        "line_end": 4,
        "column_start": 0,
        "column_end": null
      },
      "evidence": {
        "snippet": "from backend.services.auth import verify_token\n",
        "language": "python",
        "highlight_lines": [4]
      },
      "cwe_id": null,
      "owasp_category": null
    }
  ],
  "component_graph": {
    "nodes": [
      {
        "id": "backend.core",
        "name": "core",
        "path": "backend/core",
        "layer": "APPLICATION",
        "coupling": {
          "afferent": 2,
          "efferent": 1,
          "instability": 0.33,
          "total_loc": 24,
          "file_count": 2
        },
        "files": ["backend/core/engine.py", "backend/core/config.py"]
      }
    ],
    "edges": [
      {
        "id": "673cfc82-b7e8-5b4d-9ea8-228741369796",
        "source": "backend.core",
        "target": "backend.services",
        "weight": 1,
        "is_cycle": true
      }
    ],
    "circular_components_count": 1,
    "cycles": [["backend.core", "backend.services"]]
  },
  "diagnostics": []
}
```

---

### 3.2 List Registered Analysis Rules
`GET /api/v1/rules`

Returns the complete catalog of registered static analysis rules sorted deterministically by `rule_id`.

#### Response (`200 OK`)
```json
{
  "total_rules": 22,
  "rules": [
    {
      "rule_id": "ARC-001",
      "name": "Circular Dependency",
      "category": "ARCHITECTURE",
      "evidence_type": "DETERMINISTIC",
      "severity": "HIGH",
      "confidence": "HIGH",
      "description": "Detects mutual and transitive import cycles between source modules.",
      "remediation": "Extract shared types or introduce dependency inversion.",
      "supported_languages": ["python", "javascript", "typescript"],
      "frameworks": [],
      "cwe_id": null,
      "owasp_category": null,
      "rationale": "Circular dependencies cause initialization deadlocks and impede refactoring."
    }
  ]
}
```

---

### 3.3 Inspect Single Rule Details
`GET /api/v1/rules/{rule_id}`

Retrieves complete metadata for an individual rule. Lookup is case-insensitive.

#### Example: `GET /api/v1/rules/ARC-005`
```json
{
  "rule_id": "ARC-005",
  "name": "Layer Boundary Inversion",
  "category": "ARCHITECTURE",
  "evidence_type": "HEURISTIC",
  "severity": "HIGH",
  "confidence": "MEDIUM",
  "description": "Prohibited upward dependency from lower infrastructure or utility layer to higher presentation or domain layer.",
  "remediation": "Invert dependency using interfaces or abstract base classes.",
  "supported_languages": ["python", "javascript", "typescript"],
  "frameworks": [],
  "cwe_id": null,
  "owasp_category": null,
  "rationale": "Violates Clean Architecture boundary rules."
}
```

---

### 3.4 Service Health Checks
- `GET /health`: Root service health check returning uptime and backend component readiness.
- `GET /api/v1/health`: API v1 health check.

---

## 4. Error Handling & Status Codes

All API errors return standard HTTP status codes with a structured error envelope:

```json
{
  "code": "NOT_FOUND",
  "message": "Repository path does not exist: 'nonexistent_directory'",
  "details": {
    "path": "nonexistent_directory"
  }
}
```

| HTTP Status | Error Code | Description |
| :--- | :--- | :--- |
| **400 Bad Request** | `INVALID_PATH` | Path is empty, syntax is invalid, or points to a file instead of a directory. |
| **403 Forbidden** | `SECURITY_POLICY_VIOLATION` | Path violates local filesystem security policy (e.g. drive root or protected system directory). |
| **404 Not Found** | `NOT_FOUND` / `RULE_NOT_FOUND` | Repository path does not exist, or requested `rule_id` is unknown. |
| **422 Unprocessable** | `VALIDATION_ERROR` | Request body failed Pydantic schema validation. |
| **500 Internal Error** | `INTERNAL_ANALYSIS_ERROR` | Unexpected unhandled engine failure (stack traces are logged internally, not leaked). |

---

## 5. Filesystem Security Boundary

CodeSentinel implements explicit security controls for local filesystem access:
1. **Canonical Path Resolution**: All inputs are resolved via `Path.resolve()`.
2. **Directory Verification**: The path must exist and must be a directory (`is_dir() == True`).
3. **Drive Root Rejection**: Analysis cannot target drive roots (`C:\`, `/`).
4. **Protected System Directory Rejection**: Analysis cannot target `C:\Windows`, `C:\Program Files`, `/etc`, `/usr`, `/bin`, `/proc`, or `/sys`.
5. **Safe Ingestion**: Directory traversal ignores symlink chains (`followlinks=False`), skipping `.git`, `node_modules`, `venv`, and `__pycache__`.
6. **Zero Code Execution**: Analyzed files are parsed strictly as AST data tokens; no code is imported or executed, and no external commands are spawned.
7. **Bounded Evidence Snippets**: The API only transmits bounded finding snippets; no open file browser endpoint is provided.

---

## 6. CLI Usability & Filtering

The CLI (`codesentinel`) provides cumulative severity and category filtering:

```bash
# Analyze target repository
codesentinel analyze path/to/repo

# Filter by severity (HIGH includes CRITICAL and HIGH)
codesentinel analyze path/to/repo --severity HIGH

# Filter by category
codesentinel analyze path/to/repo --category SECURITY
codesentinel analyze path/to/repo --category ARCHITECTURE

# Filter by specific rule ID
codesentinel analyze path/to/repo --rule ARC-001

# Combine filters with JSON output
codesentinel analyze path/to/repo --category ARCHITECTURE --severity HIGH --format json
```

---

## 7. Running the Developer UI

Start the backend and frontend in separate terminals:

```bash
# Terminal 1: Backend
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Frontend
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser. Enter any local repository path and click **Analyze** to inspect health scores, findings, code evidence in Monaco, and the subsystem architecture graph in React Flow.
