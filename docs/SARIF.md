# CodeSentinel SARIF Specification & Integration Guide

## Overview

CodeSentinel provides strict compliance with the **OASIS Static Analysis Results Interchange Format (SARIF) version 2.1.0** standard.

SARIF is an industry-standard JSON format designed for static analysis tools to export defect findings to CI platforms (GitHub Code Scanning, GitLab SAST, Azure DevOps) and IDE extensions (VS Code SARIF Viewer).

---

## SARIF Document Structure

When `--format sarif` is specified, CodeSentinel outputs a self-contained, schema-valid SARIF v2.1.0 JSON document conforming to schema:
`https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CodeSentinel",
          "semanticVersion": "0.1.0",
          "informationUri": "https://github.com/Rudradev02/CodeSentinel",
          "rules": [ ... ]
        }
      },
      "artifacts": [ ... ],
      "results": [ ... ],
      "versionControlProvenance": [ ... ]
    }
  ]
}
```

---

## Mapping Schema

### 1. Severity to SARIF Level Mapping

CodeSentinel's five-tier severity levels map deterministically to the four SARIF result levels:

| CodeSentinel Severity | SARIF Level | GitHub / GitLab Representation |
|---|---|---|
| `CRITICAL` | `error` | Red Alert / Critical Blocking |
| `HIGH` | `error` | Red Alert / High Priority |
| `MEDIUM` | `warning` | Yellow Warning |
| `LOW` | `note` | Blue Informational Note |
| `INFO` | `note` | Informational Annotation |

---

### 2. Rule Definitions (`tool.driver.rules`)

Each distinct rule referenced in the findings is defined in `tool.driver.rules` with:
- `id`: Unique identifier (e.g. `SEC-PY-001`, `ARC-001`).
- `name`: Clean PascalCase rule identifier (e.g. `HardcodedSecretKey`).
- `shortDescription.text`: Brief human-readable title.
- `fullDescription.text`: Detailed technical description.
- `defaultConfiguration.level`: Default severity level (`error`, `warning`, `note`).
- `help.text`: Step-by-step remediation instructions.
- `properties`: Custom metadata:
  - `category`: `SECURITY` or `ARCHITECTURE`.
  - `confidence`: `HIGH`, `MEDIUM`, or `LOW`.
  - `cwe`: CWE identifier (e.g. `CWE-798`) when applicable.
  - `owasp`: OWASP Top 10 category (e.g. `A07:2021`) when applicable.
  - `rationale`: Security or architectural justification.

---

### 3. Location & Coordinate Normalization (`results[].locations`)

- **Artifact URIs**: Always formatted as repository-relative forward-slash POSIX paths (`src/config/secrets.py`), stripping leading slashes or Windows backslashes.
- **Base URI ID**: Marked with `uriBaseId: "%SRCROOT%"` for automatic checkout root resolution across different CI agents.
- **Line Offsets**: Standard 1-based integer indexing (`startLine >= 1`).
- **Column Offsets**: Converted from internal 0-based character offsets to SARIF 1-based columns (`startColumn = col_start + 1`).
- **Code Snippets**: Embedded directly in `region.snippet.text` for contextual preview in GitHub PR annotations and code review diffs.

---

### 4. Git Provenance Metadata (`versionControlProvenance`)

When executing in a Git-tracked workspace, CodeSentinel extracts local commit metadata and populates `runs[0].versionControlProvenance`:

```json
"versionControlProvenance": [
  {
    "repositoryUri": "/path/to/local/repo",
    "revisionId": "4a7b1c3e8f92a10d9e7b2354c01f3b890a9821ef",
    "branch": "feature/refactor-auth",
    "properties": {
      "isDirty": false
    }
  }
]
```

---

### 5. Data-Flow & Multi-File Execution Paths (`results[].codeFlows`)

For data-flow findings (both intraprocedural in Phase 13 and interprocedural in Phase 15), CodeSentinel generates standard SARIF `codeFlows` containing ordered `threadFlows`:

- **Intraprocedural Flows**: Single-function source-to-sink variable propagation steps with step expressions and operations.
- **Interprocedural Flows (Phase 15 & Phase 16)**: Multi-file execution paths traversing cross-file function calls:
  - Source step marked `importance: "essential"`.
  - Intermediate call site steps with `importance: "important"`, tracking `caller_function() -> callee_function(param) [action]`.
  - Sink step with `importance: "essential"` marking the dangerous execution point.
  - Every unique file in the execution chain is registered in `runs[0].artifacts` with `%SRCROOT%` URI base IDs.
  - **Type & Context Property Bags (Phase 16)**: Thread flow step locations include custom property bags:
    - `properties.typeConfidence`: `"KNOWN"`, `"LIKELY"`, `"AMBIGUOUS"`, or `"UNKNOWN"`.
    - `properties.receiverType`: Qualified receiver class name (e.g. `app.repo.UserRepository`).
    - `properties.contextId`: Call-string context identifier (e.g. `c8f1b2`).
    - Enriched human-readable message: `Call: caller() -> callee(param) [Receiver: KNOWN (UserRepository), Context: c8f1b2] [action]`.

---

## CLI Usage

```bash
# Output SARIF to stdout
codesentinel analyze /path/to/repo --format sarif

# Write SARIF to file for GitHub Actions upload
codesentinel analyze /path/to/repo --format sarif --output codesentinel.sarif

# Combine with baseline regression gating
codesentinel analyze /path/to/repo --baseline baseline.json --fail-on-regression HIGH --format sarif -o report.sarif
```
