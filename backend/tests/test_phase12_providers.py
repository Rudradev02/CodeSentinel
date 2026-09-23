"""Unit tests for Phase 12 AI Providers (OpenRouter and Ollama) with mocked HTTP transport."""

import json
from unittest.mock import MagicMock, patch
import httpx
import pytest

from backend.app.services.ai.providers.base import (
    AIModelNotFoundError,
    AIProviderError,
    AIProviderTimeoutError,
)
from backend.app.services.ai.providers.ollama import OllamaProvider
from backend.app.services.ai.providers.openrouter import OpenRouterProvider


def test_openrouter_success():
    """Verify OpenRouterProvider parses choices content and usage correctly."""
    mock_payload = {
        "finding_id": "test-finding-123",
        "is_likely_true_positive": True,
        "confidence_score": 0.95,
        "risk_summary": "High risk issue",
    }
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": json.dumps(mock_payload)}}],
        "usage": {"prompt_tokens": 120, "completion_tokens": 80},
    }

    provider = OpenRouterProvider(api_key="test-key-mock", max_retries=1)

    with patch("httpx.Client.post", return_value=mock_response):
        res = provider.generate_sync(prompt="test", system_prompt="system")

        assert res.provider_name == "openrouter"
        assert res.parsed_json == mock_payload
        assert res.prompt_tokens == 120
        assert res.completion_tokens == 80


def test_openrouter_strips_markdown_code_fences():
    """Verify OpenRouterProvider extracts JSON wrapped in ```json code fences."""
    raw_markdown = """```json
{
  "finding_id": "test-123",
  "is_likely_true_positive": false,
  "confidence_score": 0.2
}
```"""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": raw_markdown}}],
        "usage": {},
    }

    provider = OpenRouterProvider(api_key="test-key-mock", max_retries=1)

    with patch("httpx.Client.post", return_value=mock_response):
        res = provider.generate_sync(prompt="test", system_prompt="system")
        assert res.parsed_json is not None
        assert res.parsed_json["is_likely_true_positive"] is False


def test_openrouter_missing_api_key_raises():
    """Verify missing API key fails fast with AIProviderError."""
    provider = OpenRouterProvider(api_key="")
    with pytest.raises(AIProviderError, match="API key is missing"):
        provider.generate_sync(prompt="test", system_prompt="system")


def test_ollama_success():
    """Verify OllamaProvider queries local daemon and parses JSON output."""
    mock_payload = {
        "finding_id": "ollama-finding-456",
        "is_likely_true_positive": True,
        "confidence_score": 0.88,
    }
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"content": json.dumps(mock_payload)},
        "prompt_eval_count": 95,
        "eval_count": 65,
    }

    provider = OllamaProvider(base_url="http://localhost:11434")

    with patch("httpx.Client.post", return_value=mock_response):
        res = provider.generate_sync(prompt="test", system_prompt="system")
        assert res.provider_name == "ollama"
        assert res.parsed_json == mock_payload
        assert res.prompt_tokens == 95
        assert res.completion_tokens == 65


def test_ollama_model_not_found():
    """Verify HTTP 404 from Ollama maps to AIModelNotFoundError."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 404
    mock_response.text = "model 'unknown:latest' not found"

    provider = OllamaProvider(default_model="unknown:latest")

    with patch("httpx.Client.post", return_value=mock_response):
        with pytest.raises(AIModelNotFoundError, match="ollama pull"):
            provider.generate_sync(prompt="test", system_prompt="system")


def test_ollama_connection_error():
    """Verify connection error maps to friendly AIProviderError."""
    provider = OllamaProvider(base_url="http://localhost:11434")

    with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
        with pytest.raises(AIProviderError, match="Is Ollama running"):
            provider.generate_sync(prompt="test", system_prompt="system")
