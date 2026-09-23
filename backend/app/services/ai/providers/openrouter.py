"""OpenRouter LLM provider implementation for cloud model inference."""

import json
import logging
import re
import time
from typing import Any, Optional
import httpx

from backend.app.services.ai.providers.base import (
    AIProviderError,
    AIProviderTimeoutError,
    AIRateLimitError,
    BaseLLMProvider,
    LLMResponse,
)

logger = logging.getLogger(__name__)


class OpenRouterProvider(BaseLLMProvider):
    """Integrates with OpenRouter API for cloud models with retries and backoff."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://openrouter.ai/api/v1",
        default_model: str = "anthropic/claude-3.5-sonnet",
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.timeout = timeout
        self.max_retries = max_retries

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/Rudradev02/CodeSentinel",
            "X-Title": "CodeSentinel Security Auditor",
            "Content-Type": "application/json",
        }

    def _build_payload(self, prompt: str, system_prompt: str, model: Optional[str]) -> dict[str, Any]:
        return {
            "model": model or self.default_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
        }

    @staticmethod
    def _extract_json(raw_text: str) -> Optional[dict[str, Any]]:
        """Clean markdown backticks if present and parse JSON."""
        cleaned = raw_text.strip()
        # Strip ```json ... ``` wrapper if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        try:
            return json.loads(cleaned)
        except Exception:
            return None

    def generate_sync(
        self,
        prompt: str,
        system_prompt: str,
        json_schema: Optional[dict[str, Any]] = None,
        model: Optional[str] = None,
    ) -> LLMResponse:
        """Execute synchronous inference via OpenRouter API with exponential retries."""
        if not self.api_key:
            raise AIProviderError("OpenRouter API key is missing or not configured.")

        url = f"{self.base_url}/chat/completions"
        payload = self._build_payload(prompt, system_prompt, model)
        headers = self._get_headers()

        last_error = None
        for attempt in range(self.max_retries):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, json=payload, headers=headers)

                    if resp.status_code == 429:
                        wait_seconds = 2**attempt
                        logger.warning("OpenRouter 429 Rate Limit encountered. Retrying in %ds...", wait_seconds)
                        time.sleep(wait_seconds)
                        continue

                    if resp.status_code >= 500:
                        wait_seconds = 2**attempt
                        logger.warning("OpenRouter %d server error. Retrying in %ds...", resp.status_code, wait_seconds)
                        time.sleep(wait_seconds)
                        continue

                    if resp.status_code != 200:
                        raise AIProviderError(f"OpenRouter HTTP {resp.status_code}: {resp.text}")

                    data = resp.json()
                    choice = data["choices"][0]["message"]
                    raw_content = choice.get("content", "")
                    parsed = self._extract_json(raw_content)

                    usage = data.get("usage", {})
                    return LLMResponse(
                        raw_content=raw_content,
                        parsed_json=parsed,
                        model_name=payload["model"],
                        provider_name="openrouter",
                        prompt_tokens=usage.get("prompt_tokens"),
                        completion_tokens=usage.get("completion_tokens"),
                    )

            except httpx.TimeoutException as exc:
                last_error = AIProviderTimeoutError(f"OpenRouter request timed out after {self.timeout}s: {exc}")
                time.sleep(2**attempt)
            except Exception as exc:
                if isinstance(exc, (AIProviderError, AIProviderTimeoutError)):
                    raise
                last_error = AIProviderError(f"OpenRouter connection error: {exc}")
                time.sleep(2**attempt)

        raise last_error or AIProviderError("OpenRouter request failed after maximum retries.")

    async def generate_async(
        self,
        prompt: str,
        system_prompt: str,
        json_schema: Optional[dict[str, Any]] = None,
        model: Optional[str] = None,
    ) -> LLMResponse:
        """Execute asynchronous inference via OpenRouter API with retries."""
        if not self.api_key:
            raise AIProviderError("OpenRouter API key is missing or not configured.")

        url = f"{self.base_url}/chat/completions"
        payload = self._build_payload(prompt, system_prompt, model)
        headers = self._get_headers()

        last_error = None
        import asyncio

        for attempt in range(self.max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, json=payload, headers=headers)

                    if resp.status_code == 429:
                        await asyncio.sleep(2**attempt)
                        continue

                    if resp.status_code >= 500:
                        await asyncio.sleep(2**attempt)
                        continue

                    if resp.status_code != 200:
                        raise AIProviderError(f"OpenRouter HTTP {resp.status_code}: {resp.text}")

                    data = resp.json()
                    choice = data["choices"][0]["message"]
                    raw_content = choice.get("content", "")
                    parsed = self._extract_json(raw_content)

                    usage = data.get("usage", {})
                    return LLMResponse(
                        raw_content=raw_content,
                        parsed_json=parsed,
                        model_name=payload["model"],
                        provider_name="openrouter",
                        prompt_tokens=usage.get("prompt_tokens"),
                        completion_tokens=usage.get("completion_tokens"),
                    )

            except httpx.TimeoutException as exc:
                last_error = AIProviderTimeoutError(f"OpenRouter request timed out after {self.timeout}s: {exc}")
                await asyncio.sleep(2**attempt)
            except Exception as exc:
                if isinstance(exc, (AIProviderError, AIProviderTimeoutError)):
                    raise
                last_error = AIProviderError(f"OpenRouter connection error: {exc}")
                await asyncio.sleep(2**attempt)

        raise last_error or AIProviderError("OpenRouter request failed after maximum retries.")
