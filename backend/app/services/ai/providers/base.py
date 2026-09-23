"""Abstract base class and error definitions for LLM providers."""

from abc import ABC, abstractmethod
from typing import Any, Optional
from pydantic import BaseModel, Field


class LLMResponse(BaseModel):
    """Normalized response payload emitted by all LLM providers."""

    raw_content: str = Field(..., description="Raw text response from the model")
    parsed_json: Optional[dict[str, Any]] = Field(default=None, description="Parsed JSON dictionary if successful")
    model_name: str = Field(..., description="Model identifier that produced this response")
    provider_name: str = Field(..., description="Provider name (openrouter, ollama)")
    prompt_tokens: Optional[int] = Field(default=None, description="Input tokens consumed")
    completion_tokens: Optional[int] = Field(default=None, description="Output tokens produced")


class AIProviderError(Exception):
    """Base exception for all AI provider communication failures."""
    pass


class AIProviderTimeoutError(AIProviderError):
    """Raised when an AI provider times out during generation."""
    pass


class AIRateLimitError(AIProviderError):
    """Raised when an external AI provider responds with HTTP 429 rate limit."""
    pass


class AIModelNotFoundError(AIProviderError):
    """Raised when the requested model is not downloaded or available on the host."""
    pass


class BaseLLMProvider(ABC):
    """Interface isolating LLM network transport from orchestration logic."""

    @abstractmethod
    def generate_sync(
        self,
        prompt: str,
        system_prompt: str,
        json_schema: Optional[dict[str, Any]] = None,
    ) -> LLMResponse:
        """Synchronous generation method for Celery worker tasks."""
        pass

    @abstractmethod
    async def generate_async(
        self,
        prompt: str,
        system_prompt: str,
        json_schema: Optional[dict[str, Any]] = None,
    ) -> LLMResponse:
        """Asynchronous generation method for FastAPI endpoints."""
        pass
