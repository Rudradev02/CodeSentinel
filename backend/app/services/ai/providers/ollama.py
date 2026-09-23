"""Ollama LLM provider implementation for local, air-gapped model inference."""

import json
import logging
import re
from typing import Any, Optional
import httpx

from backend.app.services.ai.providers.base import (
    AIModelNotFoundError,
    AIProviderError,
    AIProviderTimeoutError,
    BaseLLMProvider,
    LLMResponse,
)

logger = logging.getLogger(__name__)


class OllamaProvider(BaseLLMProvider):
    """Integrates with local Ollama daemon for 100% air-gapped local model inference."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        default_model: str = "deepseek-coder:6.7b",
        connect_timeout: float = 5.0,
        generate_timeout: float = 60.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.timeout = httpx.Timeout(generate_timeout, connect=connect_timeout)

    def _build_payload(self, prompt: str, system_prompt: str, model: Optional[str]) -> dict[str, Any]:
        return {
            "model": model or self.default_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "format": "json",
            "stream": False,
        }

    @staticmethod
    def _extract_json(raw_text: str) -> Optional[dict[str, Any]]:
        cleaned = raw_text.strip()
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
        """Synchronously query local Ollama daemon."""
        url = f"{self.base_url}/api/chat"
        payload = self._build_payload(prompt, system_prompt, model)

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)

                if resp.status_code == 404:
                    raise AIModelNotFoundError(
                        f"Ollama model '{payload['model']}' not found. Run 'ollama pull {payload['model']}' to install."
                    )

                if resp.status_code != 200:
                    raise AIProviderError(f"Ollama daemon returned HTTP {resp.status_code}: {resp.text}")

                data = resp.json()
                raw_content = data.get("message", {}).get("content", "")
                parsed = self._extract_json(raw_content)

                return LLMResponse(
                    raw_content=raw_content,
                    parsed_json=parsed,
                    model_name=payload["model"],
                    provider_name="ollama",
                    prompt_tokens=data.get("prompt_eval_count"),
                    completion_tokens=data.get("eval_count"),
                )

        except httpx.ConnectError as exc:
            raise AIProviderError(f"Could not connect to Ollama daemon at {self.base_url}. Is Ollama running?: {exc}")
        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError(f"Ollama generation timed out: {exc}")
        except Exception as exc:
            if isinstance(exc, (AIProviderError, AIModelNotFoundError, AIProviderTimeoutError)):
                raise
            raise AIProviderError(f"Ollama provider error: {exc}")

    async def generate_async(
        self,
        prompt: str,
        system_prompt: str,
        json_schema: Optional[dict[str, Any]] = None,
        model: Optional[str] = None,
    ) -> LLMResponse:
        """Asynchronously query local Ollama daemon."""
        url = f"{self.base_url}/api/chat"
        payload = self._build_payload(prompt, system_prompt, model)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload)

                if resp.status_code == 404:
                    raise AIModelNotFoundError(
                        f"Ollama model '{payload['model']}' not found. Run 'ollama pull {payload['model']}' to install."
                    )

                if resp.status_code != 200:
                    raise AIProviderError(f"Ollama daemon returned HTTP {resp.status_code}: {resp.text}")

                data = resp.json()
                raw_content = data.get("message", {}).get("content", "")
                parsed = self._extract_json(raw_content)

                return LLMResponse(
                    raw_content=raw_content,
                    parsed_json=parsed,
                    model_name=payload["model"],
                    provider_name="ollama",
                    prompt_tokens=data.get("prompt_eval_count"),
                    completion_tokens=data.get("eval_count"),
                )

        except httpx.ConnectError as exc:
            raise AIProviderError(f"Could not connect to Ollama daemon at {self.base_url}. Is Ollama running?: {exc}")
        except httpx.TimeoutException as exc:
            raise AIProviderTimeoutError(f"Ollama generation timed out: {exc}")
        except Exception as exc:
            if isinstance(exc, (AIProviderError, AIModelNotFoundError, AIProviderTimeoutError)):
                raise
            raise AIProviderError(f"Ollama provider error: {exc}")
