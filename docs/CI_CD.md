# CodeSentinel CI/CD Automation & Baseline Gating Guide

## Overview

CodeSentinel provides native, deterministic CI/CD automation capabilities designed for modern continuous integration pipelines (GitHub Actions, GitLab CI, Azure DevOps, Bitbucket Pipelines).

Key architectural advantages for CI/CD:
- **Zero External Infrastructure**: 100% offline and standalone; requires no databases, Redis, Celery workers, or remote cloud services.
- **Deterministic & Fast**: Completes audits in milliseconds to single-digit seconds without running analyzed source code.
- **OASIS SARIF v2.1.0 Standard**: Out-of-the-box integration with GitHub Code Scanning, GitLab SAST, and VS Code.
- **Differential Baseline Analysis**: Evaluates regressions against historical baseline reports, preventing PR build failures caused by pre-existing technical debt while strictly blocking new violations.

---

## Exit Code Semantics

CodeSentinel conforms to strict POSIX exit code conventions for automated build runners:

| Exit Code | Meaning | Action by CI Runner |
|---|---|---|
| `0` | **Success / Policy Passed** | Build continues normally. |
| `1` | **Operational Error** | Path not found, invalid syntax, unparseable baseline JSON, or file I/O permissions error. |
| `2` | **Policy Threshold Violation** | One or more findings triggered `--fail-on` or newly introduced regressions triggered `--fail-on-regression`. |

---

## CLI Automation Flags & Formats

### Declarative Configuration (`.codesentinel.yml`)
Rather than passing lengthy arguments to every CI run, place a `.codesentinel.yml` in the root of your repository:
```yaml
version: 1
analysis:
  enabled_rules: []      # Empty = all registered rules active
  disabled_rules:
    - ARC-008
  fail_on_severity: HIGH
  arc_002_coupling_threshold: 12
paths:
  exclude:
    - "tests/**"
    - "legacy/**"
reporting:
  format: junit
  output: codesentinel-junit.xml
```

Precedence order: **CLI Arguments > `.codesentinel.yml` > Built-in Defaults**.

### Multi-Target Enterprise Reporters
CodeSentinel supports 7 output formats:
```bash
# 1. PR Review Markdown table (ideal for GitHub/GitLab PR comment bots)
codesentinel analyze . --format markdown --output pr-summary.md

# 2. Standalone Zero-External-CDN HTML report (interactive dark theme, inline SVG KPI charts)
codesentinel analyze . --format html --output report.html

# 3. JUnit XML (standard test suite format for Jenkins, GitHub Actions, CircleCI)
codesentinel analyze . --format junit --output test-results.xml

# 4. GitLab Code Quality JSON (native GitLab MR code quality widget)
codesentinel analyze . --format gitlab --output gl-code-quality-report.json

# 5. OASIS SARIF v2.1.0 (GitHub Code Scanning, Azure DevOps)
codesentinel analyze . --format sarif --output scan.sarif

# 6. Structured JSON (custom tooling / scripting)
codesentinel analyze . --format json --output scan.json

# 7. Rich ANSI Terminal (default)
codesentinel analyze . --format terminal
```

### Pre-Commit Hook Integration (`.pre-commit-hooks.yaml`)
Integrate CodeSentinel into local developer git hooks using `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/Rudradev02/CodeSentinel
    rev: v0.14.0
    hooks:
      - id: codesentinel-scan
        args: ["--fail-on", "HIGH"]
      - id: codesentinel-diff
        args: ["--baseline", ".codesentinel-baseline.json", "--fail-on-regression", "HIGH"]
```

### Differential Baseline & Regression Gating
```bash
# Analyze PR branch and fail ONLY if newly introduced violations are HIGH or CRITICAL
codesentinel analyze . --baseline baseline.json --fail-on-regression HIGH

# Generate SARIF report for GitHub Code Scanning
codesentinel analyze . --format sarif --output codesentinel.sarif

# Compare two stored historical reports directly
codesentinel compare baseline.json current.json --fail-on-regression MEDIUM
```

---

## GitHub Actions Workflows

### 1. Pull Request Regression Gate & SARIF Code Scanning
Save as `.github/workflows/codesentinel.yml`:

```yaml
name: CodeSentinel Static Audit & Gating

on:
  pull_request:
    branches: [ main, master ]
  push:
    branches: [ main, master ]

jobs:
  audit:
    name: CodeSentinel Security & Architecture Gate
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install CodeSentinel Analyzer
        run: |
          python -m pip install --upgrade pip
          pip install -e .

      - name: Restore Baseline Report from Cache
        if: github.event_name == 'pull_request'
        uses: actions/cache/restore@v4
        with:
          path: .codesentinel-baseline.json
          key: codesentinel-baseline-${{ github.base_ref }}
          restore-keys: |
            codesentinel-baseline-main
            codesentinel-baseline-master

      - name: Run Audit on Main (Generate Baseline)
        if: github.event_name == 'push'
        run: |
          codesentinel analyze . --format json --output .codesentinel-baseline.json
          codesentinel analyze . --format sarif --output codesentinel.sarif

      - name: Save Baseline Report to Cache
        if: github.event_name == 'push'
        uses: actions/cache/save@v4
        with:
          path: .codesentinel-baseline.json
          key: codesentinel-baseline-${{ github.ref_name }}-${{ github.sha }}

      - name: Run Differential Audit on PR (Gate Regressions Only)
        if: github.event_name == 'pull_request'
        run: |
          if [ -f .codesentinel-baseline.json ]; then
            echo "Baseline report found. Running differential analysis..."
            codesentinel analyze . \
              --baseline .codesentinel-baseline.json \
              --fail-on-regression HIGH \
              --format sarif \
              --output codesentinel.sarif
          else
            echo "No baseline report cached. Running full policy check..."
            codesentinel analyze . \
              --fail-on HIGH \
              --format sarif \
              --output codesentinel.sarif
          fi

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: codesentinel.sarif
          category: codesentinel-sast
```

---

## GitLab CI/CD Pipeline

Save in `.gitlab-ci.yml`:

```yaml
stages:
  - test

codesentinel_sast:
  stage: test
  image: python:3.11-slim
  script:
    - pip install -e .
    - |
      if [ -f "baseline.json" ]; then
        codesentinel analyze . --baseline baseline.json --fail-on-regression HIGH --format sarif --output gl-sast-report.sarif
      else
        codesentinel analyze . --fail-on HIGH --format sarif --output gl-sast-report.sarif
      fi
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    paths:
      - gl-sast-report.sarif
    when: always
```

---

## Azure DevOps Pipelines

Save in `azure-pipelines.yml`:

```yaml
trigger:
  - main
pr:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'

  - script: |
      python -m pip install --upgrade pip
      pip install -e .
      codesentinel analyze . --format sarif --output $(Build.ArtifactStagingDirectory)/CodeSentinel.sarif --fail-on HIGH
    displayName: 'Execute CodeSentinel Static Audit'

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)/CodeSentinel.sarif'
      ArtifactName: 'CodeAnalysisLogs'
      publishLocation: 'Container'
    condition: always()
```

---

## Best Practices for CI Adoption

1. **Phase 1: Zero-Friction Visibility**:
   Run `codesentinel analyze . --format sarif` and upload the SARIF report to Code Scanning without any `--fail-on` or `--fail-on-regression` flags. This gives teams full visibility of existing debt without interrupting delivery.
2. **Phase 2: Regression Gating (`--fail-on-regression HIGH`)**:
   Introduce the baseline cache. Developers can freely merge pull requests as long as they do not introduce *new* high/critical security vulnerabilities or architectural anti-patterns. Pre-existing baseline findings are tracked and displayed without failing the build.
3. **Phase 3: Clean Branch Enforcement (`--fail-on HIGH`)**:
   Once technical debt has been burned down or remediated on `main`, enable strict `--fail-on HIGH` to maintain an immaculate security and architecture baseline.
