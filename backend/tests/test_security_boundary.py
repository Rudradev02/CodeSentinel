"""Security boundary tests for local developer API filesystem access."""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.core.security import validate_repository_path
from backend.app.core.exceptions import SecurityPolicyViolationException
from backend.app.main import app


@pytest.fixture
def client():
    """Create test client for FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


def test_drive_root_rejected():
    """Verify attempting to analyze drive root raises SecurityPolicyViolationException."""
    # Test drive root such as C:\ or /
    root_path = Path(Path.cwd().anchor).resolve()
    with pytest.raises(SecurityPolicyViolationException) as exc_info:
        validate_repository_path(str(root_path))
    assert exc_info.value.code == "SECURITY_POLICY_VIOLATION"


def test_system_directory_rejected():
    """Verify attempting to analyze protected system directory raises SecurityPolicyViolationException."""
    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    if Path(system_root).exists():
        with pytest.raises(SecurityPolicyViolationException) as exc_info:
            validate_repository_path(system_root)
        assert exc_info.value.code == "SECURITY_POLICY_VIOLATION"


def test_api_enforces_security_policy(client: TestClient):
    """Verify API endpoint returns HTTP 403 when security boundary is violated."""
    root_path = str(Path(Path.cwd().anchor).resolve())
    response = client.post("/api/v1/analyze", json={"path": root_path})
    assert response.status_code == 403

    data = response.json()
    assert data["code"] == "SECURITY_POLICY_VIOLATION"
    assert "root" in data["message"].lower() or "protected" in data["message"].lower()
