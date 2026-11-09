"""Pluggable language-model providers. Only the standard library is used for HTTP."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol


class LLMError(RuntimeError):
    """The provider could not be reached or returned an unusable response."""


class LLMProvider(Protocol):
    def complete(self, system: str, prompt: str) -> str: ...


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
    if not url.startswith(("http://", "https://")):
        raise LLMError(f"refusing non-HTTP url: {url!r}")
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise LLMError(f"request to {url} failed: {exc}") from exc


class OllamaProvider:
    """Talks to a local Ollama server (``/api/chat``)."""

    def __init__(self, model: str, host: str = "http://localhost:11434", timeout: float = 120.0):
        self.model, self.host, self.timeout = model, host.rstrip("/"), timeout

    def complete(self, system: str, prompt: str) -> str:
        data = _post_json(
            f"{self.host}/api/chat",
            {
                "model": self.model,
                "stream": False,
                "format": "json",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            {},
            self.timeout,
        )
        try:
            return str(data["message"]["content"])
        except (KeyError, TypeError) as exc:
            raise LLMError("unexpected Ollama response shape") from exc


class OpenAICompatProvider:
    """Any server exposing the OpenAI-style ``/chat/completions`` endpoint."""

    def __init__(self, model: str, base_url: str, api_key: str, timeout: float = 120.0):
        if not api_key:
            raise LLMError("an API key is required for the OpenAI-compatible provider")
        self.model, self.base_url, self.api_key = model, base_url.rstrip("/"), api_key
        self.timeout = timeout

    def complete(self, system: str, prompt: str) -> str:
        data = _post_json(
            f"{self.base_url}/chat/completions",
            {
                "model": self.model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
            {"Authorization": f"Bearer {self.api_key}"},
            self.timeout,
        )
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError("unexpected chat-completions response shape") from exc


class FakeProvider:
    """Deterministic provider for tests: returns queued replies and records prompts."""

    def __init__(self, replies: list[str]):
        self._replies = list(replies)
        self.prompts: list[str] = []

    def complete(self, system: str, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self._replies:
            raise LLMError("FakeProvider has no replies left")
        return self._replies.pop(0)
