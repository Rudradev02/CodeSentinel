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

    def _build_payload(
        self,
        prompt: str,
        system_prompt: str,
        model: Optional[str],
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        return {
            "model": model or self.default_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": temperature,
        }

    @staticmethod
    def _extract_json(raw_text: str) -> Optional[dict[str, Any]]:
        """Clean markdown backticks if present and parse JSON robustly."""
        if not raw_text:
            return None
        cleaned = raw_text.strip()
        # Direct parse first
        try:
            return json.loads(cleaned)
        except Exception:
            pass

        # Strip standard markdown block ```json ... ```
        if cleaned.startswith("```"):
            stripped = re.sub(r"^```(?:json)?\s*", "", cleaned)
            stripped = re.sub(r"\s*```$", "", stripped)
            try:
                return json.loads(stripped.strip())
            except Exception:
                pass

        # Regex search for any fenced code block containing JSON
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except Exception:
                pass

        # Search for first outermost JSON object {...}
        brace_start = cleaned.find("{")
        brace_end = cleaned.rfind("}")
        if brace_start != -1 and brace_end > brace_start:
            try:
                return json.loads(cleaned[brace_start:brace_end + 1])
            except Exception:
                pass

        return None

FREE_MODEL_FALLBACKS = [
    "google/gemini-2.0-flash-lite-preview-02-05:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "qwen/qwen-2.5-coder-32b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
]


    def generate_sync(
        self,
        prompt: str,
        system_prompt: str,
        json_schema: Optional[dict[str, Any]] = None,
        model: Optional[str] = None,
        temperature: float = 0.1,
    ) -> LLMResponse:
        """Execute synchronous inference via OpenRouter API with exponential retries and fallback cascade."""
        if not self.api_key:
            raise AIProviderError("OpenRouter API key is missing or not configured.")

        url = f"{self.base_url}/chat/completions"
        primary_model = model or self.default_model

        # Build candidate models: if primary is a free model, add alternative free models to cascade on 429
        candidate_models = [primary_model]
        if ":free" in primary_model.lower():
            for fb in FREE_MODEL_FALLBACKS:
                if fb not in candidate_models:
                    candidate_models.append(fb)

        last_error = None
        start_t = time.perf_counter()

        for curr_model in candidate_models:
            payload = self._build_payload(prompt, system_prompt, curr_model, temperature=temperature)
            headers = self._get_headers()

            for attempt in range(self.max_retries):
                try:
                    with httpx.Client(timeout=self.timeout) as client:
                        resp = client.post(url, json=payload, headers=headers)

                        if resp.status_code == 429:
                            last_error = AIProviderError(f"OpenRouter 429 Rate Limit on {curr_model}: {resp.text}")
                            wait_seconds = 2**attempt
                            logger.warning("OpenRouter 429 Rate Limit encountered on %s. Retrying in %ds...", curr_model, wait_seconds)
                            if attempt == self.max_retries - 1:
                                break
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
                        latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                        return LLMResponse(
                            raw_content=raw_content,
                            parsed_json=parsed,
                            model_name=curr_model,
                            provider_name="openrouter",
                            prompt_tokens=usage.get("prompt_tokens"),
                            completion_tokens=usage.get("completion_tokens"),
                            latency_ms=latency_ms,
                        )

                except httpx.TimeoutException as exc:
                    last_error = AIProviderTimeoutError(f"OpenRouter request timed out after {self.timeout}s: {exc}")
                    time.sleep(2**attempt)
                except Exception as exc:
                    if isinstance(exc, (AIProviderError, AIProviderTimeoutError)):
                        last_error = exc
                        if "429" not in str(exc):
                            raise
                    else:
                        last_error = AIProviderError(f"OpenRouter connection error: {exc}")
                    time.sleep(2**attempt)

            if len(candidate_models) > 1 and curr_model != candidate_models[-1]:
                next_cand = candidate_models[candidate_models.index(curr_model) + 1]
                logger.warning(
                    "Model %s rate limited. Automatically cascading to next free fallback model: %s...",
                    curr_model,
                    next_cand,
                )

        raise last_error or AIProviderError("OpenRouter request failed after maximum retries.")

    async def generate_async(
        self,
        prompt: str,
        system_prompt: str,
        json_schema: Optional[dict[str, Any]] = None,
        model: Optional[str] = None,
        temperature: float = 0.1,
    ) -> LLMResponse:
        """Execute asynchronous inference via OpenRouter API with retries and fallback cascade."""
        if not self.api_key:
            raise AIProviderError("OpenRouter API key is missing or not configured.")

        url = f"{self.base_url}/chat/completions"
        primary_model = model or self.default_model

        candidate_models = [primary_model]
        if ":free" in primary_model.lower():
            for fb in FREE_MODEL_FALLBACKS:
                if fb not in candidate_models:
                    candidate_models.append(fb)

        last_error = None
        start_t = time.perf_counter()
        import asyncio

        for curr_model in candidate_models:
            payload = self._build_payload(prompt, system_prompt, curr_model, temperature=temperature)
            headers = self._get_headers()

            for attempt in range(self.max_retries):
                try:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        resp = await client.post(url, json=payload, headers=headers)

                        if resp.status_code == 429:
                            last_error = AIProviderError(f"OpenRouter 429 Rate Limit on {curr_model}: {resp.text}")
                            wait_seconds = 2**attempt
                            logger.warning("OpenRouter 429 Rate Limit encountered on %s. Retrying in %ds...", curr_model, wait_seconds)
                            if attempt == self.max_retries - 1:
                                break
                            await asyncio.sleep(wait_seconds)
                            continue

                        if resp.status_code >= 500:
                            wait_seconds = 2**attempt
                            logger.warning("OpenRouter %d server error. Retrying in %ds...", resp.status_code, wait_seconds)
                            await asyncio.sleep(wait_seconds)
                            continue

                        if resp.status_code != 200:
                            raise AIProviderError(f"OpenRouter HTTP {resp.status_code}: {resp.text}")

                        data = resp.json()
                        choice = data["choices"][0]["message"]
                        raw_content = choice.get("content", "")
                        parsed = self._extract_json(raw_content)

                        usage = data.get("usage", {})
                        latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                        return LLMResponse(
                            raw_content=raw_content,
                            parsed_json=parsed,
                            model_name=curr_model,
                            provider_name="openrouter",
                            prompt_tokens=usage.get("prompt_tokens"),
                            completion_tokens=usage.get("completion_tokens"),
                            latency_ms=latency_ms,
                        )

                except httpx.TimeoutException as exc:
                    last_error = AIProviderTimeoutError(f"OpenRouter request timed out after {self.timeout}s: {exc}")
                    await asyncio.sleep(2**attempt)
                except Exception as exc:
                    if isinstance(exc, (AIProviderError, AIProviderTimeoutError)):
                        last_error = exc
                        if "429" not in str(exc):
                            raise
                    else:
                        last_error = AIProviderError(f"OpenRouter connection error: {exc}")
                    await asyncio.sleep(2**attempt)

            if len(candidate_models) > 1 and curr_model != candidate_models[-1]:
                next_cand = candidate_models[candidate_models.index(curr_model) + 1]
                logger.warning(
                    "Model %s rate limited. Automatically cascading to next free fallback model: %s...",
                    curr_model,
                    next_cand,
                )

        raise last_error or AIProviderError("OpenRouter request failed after maximum retries.")
