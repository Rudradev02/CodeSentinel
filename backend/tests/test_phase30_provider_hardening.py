"""Unit tests for Phase 30.1 AI Provider Hardening and Go Context Extraction."""

from pathlib import Path
import tempfile
import pytest
from unittest.mock import MagicMock, patch

from backend.app.services.ai.context_builder import ContextBuilder
from backend.app.services.ai.providers.base import (
    AIInvalidResponseError,
    AIModelNotFoundError,
    AIProviderError,
    AIProviderTimeoutError,
    AIRateLimitError,
    LLMResponse,
)
from backend.app.services.ai.providers.ollama import OllamaProvider
from backend.app.services.ai.providers.openrouter import OpenRouterProvider


def test_llm_response_latency_field():
    """Verify LLMResponse accepts and retains latency_ms metric."""
    resp = LLMResponse(
        raw_content='{"status": "ok"}',
        parsed_json={"status": "ok"},
        model_name="test-model",
        provider_name="test-provider",
        prompt_tokens=10,
        completion_tokens=5,
        latency_ms=145.2,
    )
    assert resp.latency_ms == 145.2
    assert resp.parsed_json == {"status": "ok"}

    # Default latency_ms is None
    resp_none = LLMResponse(
        raw_content="raw",
        model_name="m",
        provider_name="p",
    )
    assert resp_none.latency_ms is None


def test_ollama_provider_measures_latency():
    """Verify OllamaProvider records execution latency_ms in LLMResponse."""
    provider = OllamaProvider(base_url="http://localhost:11434")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"content": '{"is_likely_true_positive": true}'},
        "prompt_eval_count": 25,
        "eval_count": 12,
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res = provider.generate_sync("prompt", "system", model="deepseek-coder:6.7b", temperature=0.2)

        assert res.provider_name == "ollama"
        assert res.model_name == "deepseek-coder:6.7b"
        assert res.parsed_json == {"is_likely_true_positive": True}
        assert res.latency_ms is not None
        assert res.latency_ms >= 0.0


def test_openrouter_provider_measures_latency():
    """Verify OpenRouterProvider records latency_ms and parses payload."""
    provider = OpenRouterProvider(api_key="test-key", default_model="anthropic/claude-3.5-sonnet")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": '{"verdict": "CONFIRMED"}'}}],
        "usage": {"prompt_tokens": 50, "completion_tokens": 20},
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res = provider.generate_sync("prompt", "system", temperature=0.0)

        assert res.provider_name == "openrouter"
        assert res.model_name == "anthropic/claude-3.5-sonnet"
        assert res.parsed_json == {"verdict": "CONFIRMED"}
        assert res.latency_ms is not None
        assert res.latency_ms >= 0.0


def test_go_ast_context_extraction():
    """Verify ContextBuilder extracts Go receiver method and imports via tree-sitter-go."""
    go_code = '''package main

import (
    "database/sql"
    "fmt"
    "net/http"
)

type UserHandler struct {
    db *sql.DB
}

// HandleUser processes user requests
func (h *UserHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("id")
    rawSQL := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", query)
    h.db.Exec(rawSQL)
}

func main() {
    fmt.Println("Server started")
}
'''
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        go_file = tmp_path / "server.go"
        go_file.write_text(go_code, encoding="utf-8")

        # Line 17 is: rawSQL := fmt.Sprintf(...) inside HandleUser method
        context = ContextBuilder.extract_context(
            repo_root=tmp_path,
            file_path="server.go",
            line_start=17,
            line_end=17,
            language="go",
        )

        assert context.enclosing_symbol_name == "UserHandler.HandleUser"
        assert context.enclosing_symbol_kind == "METHOD"
        assert "func (h *UserHandler) HandleUser" in context.enclosing_source
        assert "h.db.Exec(rawSQL)" in context.enclosing_source
        assert any("net/http" in imp for imp in context.relevant_imports)
        assert any("fmt" in imp for imp in context.relevant_imports)
        assert context.was_truncated is False
