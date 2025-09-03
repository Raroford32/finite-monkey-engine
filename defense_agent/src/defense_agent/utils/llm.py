import json
import os
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional


class OpenRouterClient:
    def __init__(self, api_key_env: str = "OPENROUTER_API_KEY", model: str = "openai/gpt-5") -> None:
        self._api_key = os.getenv(api_key_env, "").strip()
        self._model = model
        self._endpoint = "https://openrouter.ai/api/v1/chat/completions"

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.2, max_tokens: int = 800) -> str:
        if not self.is_configured():
            # Fallback minimal deterministic behavior
            return ""
        payload: Dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        req = urllib.request.Request(
            self._endpoint,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
                choices = data.get("choices", [])
                if not choices:
                    return ""
                return choices[0].get("message", {}).get("content", "")
        except urllib.error.HTTPError as e:
            return ""
        except Exception:
            return ""

