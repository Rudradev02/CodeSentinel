# CodeSentinel — REST API Specification

## 1. Overview & Protocol Design

The CodeSentinel Backend exposes a RESTful API using FastAPI. All responses adhere to standard JSON formats with explicit schema validation powered by Pydantic v2.

- **Base URL**: `/api/v1`
- **Root Health Check**: `/health` and `/api/v1/health`
- **Content Type**: `application/json`
- **Specification Format**: OpenAPI 3.1.0 Compatible

> [!IMPORTANT]
> **Phase 1 Implementation Scope**:
> In **Phase 1**, only the `/health` and `/api/v1/health` endpoints are active and implemented. All other endpoints below are documented as the formal architectural contract for subsequent phases (Phases 4, 5, 6).

---

## 2. API Endpoints Catalog

### 2.1 System & Health (Phase 1 Implemented)

#### `GET /health` and `GET /api/v1/health`
Checks backend operational status, uptime, and system readiness.

**Response `200 OK`**:
```json
{
  "status": "healthy",
  "service": "CodeSentinel API",
  "version": "0.1.0",
  "environment": "development",
  "uptime_seconds": 42.15,
  "timestamp": "2026-09-16T17:00:00.000Z",
  "components": {
    "api": "healthy",
    "analyzer_engine": "available"
  }
}
```

---

### 2.2 Repositories (Phase 4 Contract)

#### `POST /api/v1/repositories`
Registers a repository for analysis (local folder path or git clone URL).

**Request Body**:
```json
{
  "name": "ecommerce-api",
  "local_path": "/workspace/repos/ecommerce-api",
  "git_url": "https://github.com/org/ecommerce-api.git",
  "branch": "main"
}
```

**Response `201 Created`**:
```json
{
  "id": "7b8f9e6a-1234-4567-89ab-cdef01234567",
  "name": "ecommerce-api",
  "local_path": "/workspace/repos/ecommerce-api",
  "created_at": "2026-09-16T17:01:00.000Z"
}
```

#### `GET /api/v1/repositories`
Lists all registered repositories with their latest audit statuses.

---

### 2.3 Analysis Runs (Phase 4 Contract)

#### `POST /api/v1/analyses`
Triggers an asynchronous analysis run for a repository.

**Request Body**:
```json
{
  "repository_id": "7b8f9e6a-1234-4567-89ab-cdef01234567",
  "enable_ai_enrichment": true
}
```

**Response `202 Accepted`**:
```json
{
  "analysis_id": "9c1b2a3d-4567-8901-abcd-ef0123456789",
  "status": "PENDING",
  "message": "Analysis job enqueued successfully."
}
```

#### `GET /api/v1/analyses/{analysis_id}`
Retrieves complete analysis summary including file stats, risk metrics, and summary counts.

**Response `200 OK`**:
```json
{
  "id": "9c1b2a3d-4567-8901-abcd-ef0123456789",
  "repository_id": "7b8f9e6a-1234-4567-89ab-cdef01234567",
  "status": "COMPLETED",
  "detected_languages": {
    "Python": 45,
    "TypeScript": 55
  },
  "detected_frameworks": ["Django", "React"],
  "total_files": 120,
  "total_loc": 14500,
  "security_findings_count": 8,
  "architecture_findings_count": 3,
  "started_at": "2026-09-16T17:02:00.000Z",
  "completed_at": "2026-09-16T17:02:22.000Z"
}
```

---

### 2.4 Findings & Code Snippets (Phase 4/6 Contract)

#### `GET /api/v1/analyses/{analysis_id}/findings`
Query findings with filters (`category`, `severity`, `evidence_type`).

**Response `200 OK`**:
```json
[
  {
    "id": "f1a2b3c4-d5e6-7890-abcd-1234567890ab",
    "rule_id": "SEC-PY-003",
    "rule_name": "Unsafe Subprocess Execution",
    "finding_category": "SECURITY",
    "evidence_type": "DETERMINISTIC",
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "file_path": "services/exporter.py",
    "line_start": 45,
    "line_end": 45,
    "code_snippet": "subprocess.call(f'tar -czf {output_path} {target_dir}', shell=True)",
    "description": "Subprocess execution with shell=True and dynamic string interpolation allows command injection.",
    "remediation": "Pass arguments as a sequence and set shell=False.",
    "cwe_id": "CWE-78",
    "owasp_category": "A03:2021-Injection",
    "ai_enrichment": {
      "validation_status": "CONFIRMED",
      "explanation": "The target_dir variable originates from user request payload without sanitization, permitting arbitrary bash execution.",
      "remediation_suggestion": "Pass a sanitized list of arguments to subprocess.run without shell=True.",
      "unified_diff": "- subprocess.call(f'tar -czf {output_path} {target_dir}', shell=True)\n+ subprocess.run(['tar', '-czf', output_path, target_dir], check=True)",
      "confidence": 0.95
    }
  }
]
```

#### `GET /api/v1/analyses/{analysis_id}/files/{file_path}`
Retrieves file contents and finding line ranges for the Monaco Code Viewer.

---

### 2.5 Architecture Graph (Phase 4/6 Contract)

#### `GET /api/v1/analyses/{analysis_id}/graph`
Retrieves nodes and edges formatted for React Flow visualization.

**Response `200 OK`**:
```json
{
  "nodes": [
    {
      "id": "app.core.config",
      "label": "core/config.py",
      "fan_in": 12,
      "fan_out": 1,
      "is_god_module": false
    }
  ],
  "edges": [
    {
      "id": "e-core.config-app.main",
      "source": "app.main",
      "target": "app.core.config",
      "is_circular": false
    }
  ],
  "circular_dependencies": [],
  "metrics": {
    "total_modules": 45,
    "total_dependencies": 112,
    "circular_cycles_count": 0,
    "average_fan_out": 2.48
  }
}
```

---

## 3. Error Response Format

Standard RFC 7807 compliant error format:

```json
{
  "detail": {
    "error_code": "ANALYSIS_NOT_FOUND",
    "message": "Analysis run with ID '9c1b2a3d...' was not found.",
    "status_code": 404
  }
}
```
