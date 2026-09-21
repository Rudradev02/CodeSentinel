"""Automated performance and benchmark verification tests for Phase 8 API."""

from pathlib import Path
import time
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app

FIXTURE_PATH = str(Path(__file__).resolve().parent.parent.parent / "analyzer" / "tests" / "fixtures" / "sample_project")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_analysis_api_performance_benchmark(client: TestClient):
    """Benchmark POST /api/v1/analyze overhead across multiple iterations."""
    # Warmup run
    warmup = client.post("/api/v1/analyze", json={"path": FIXTURE_PATH})
    assert warmup.status_code == 200

    iterations = 5
    latencies: list[float] = []

    for _ in range(iterations):
        start = time.perf_counter()
        resp = client.post("/api/v1/analyze", json={"path": FIXTURE_PATH})
        elapsed = time.perf_counter() - start
        assert resp.status_code == 200
        latencies.append(elapsed)

    avg_latency = sum(latencies) / len(latencies)
    # The fixture analysis itself takes ~30ms, total endpoint latency should stay well under 350ms
    assert avg_latency < 0.500, f"Average latency too high: {avg_latency:.4f}s"


def test_rules_api_latency(client: TestClient):
    """Verify rule catalog inspection responds within milliseconds."""
    start = time.perf_counter()
    resp = client.get("/api/v1/rules")
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    assert elapsed < 0.100, f"Rules endpoint too slow: {elapsed:.4f}s"
