"""Dual-mode LLM gateway.

    local  : Ollama at OLLAMA_URL (air-gapped; nothing leaves the machine)
    cloud  : any OpenAI-compatible endpoint (Groq by default, then OpenRouter)
    off    : no model at all - the deterministic template report is used

Business logic never knows which provider answered. Reliability layer:
retry with exponential backoff on rate limits / 5xx, provider fall-through,
an on-disk cache keyed by the hash of the input, and a hard timeout. If every
provider fails the caller gets None and falls back to the template.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Optional

import httpx

from .. import config


class LLMGateway:
    def __init__(self, mode: Optional[str] = None):
        self.mode = (mode or config.LLM_MODE).lower()
        self._ollama_model: Optional[str] = None
        self._ollama_checked = 0.0
        self._ollama_models: list[str] = []
        self.last_error: Optional[str] = None

    # ------------------------------------------------------------ discovery
    def _ollama(self) -> Optional[str]:
        """Pick a local model: the configured one, else the best installed."""
        if time.time() - self._ollama_checked < 30:
            return self._ollama_model
        self._ollama_checked = time.time()
        self._ollama_model = None
        try:
            r = httpx.get(f"{config.OLLAMA_URL}/api/tags", timeout=2.0)
            r.raise_for_status()
            models = r.json().get("models", [])
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"Ollama not reachable at {config.OLLAMA_URL}: {type(exc).__name__}"
            self._ollama_models = []
            return None
        names = [m["name"] for m in models]
        self._ollama_models = names
        if config.OLLAMA_MODEL:
            self._ollama_model = config.OLLAMA_MODEL if config.OLLAMA_MODEL in names else None
            if not self._ollama_model:
                self.last_error = f"Ollama model '{config.OLLAMA_MODEL}' is not installed (installed: {', '.join(names) or 'none'})"
            return self._ollama_model
        for want in config.OLLAMA_PREFERRED:  # exact tag first, then the same family
            if want in names:
                self._ollama_model = want
                return want
        for want in config.OLLAMA_PREFERRED:
            fam = [n for n in names if n.split(":")[0] == want.split(":")[0]]
            if fam:
                self._ollama_model = fam[0]
                return fam[0]
        text_models = [m for m in models if "embed" not in m["name"]]
        if text_models:
            self._ollama_model = max(text_models, key=lambda m: m.get("size", 0))["name"]
        return self._ollama_model

    def chain(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        if self.mode in ("auto", "local"):
            model = self._ollama()
            if model:
                out.append(dict(kind="ollama", name="Ollama (local)", model=model, base=config.OLLAMA_URL))
        if self.mode in ("auto", "cloud"):
            if config.CLOUD_API_KEY:
                out.append(dict(kind="openai", name="Cloud (OpenAI-compatible)", model=config.CLOUD_MODEL, base=config.CLOUD_BASE_URL, key=config.CLOUD_API_KEY))
            if config.FALLBACK_API_KEY:
                out.append(dict(kind="openai", name="Cloud fallback", model=config.FALLBACK_MODEL, base=config.FALLBACK_BASE_URL, key=config.FALLBACK_API_KEY))
        return out

    def status(self) -> dict[str, Any]:
        chain = self.chain() if self.mode != "off" else []
        active = chain[0] if chain else None
        return dict(mode=self.mode, available=bool(active), provider=active["name"] if active else "Template only (no model)",
                    model=active["model"] if active else None, local=bool(active and active["kind"] == "ollama"),
                    chain=[dict(name=c["name"], model=c["model"]) for c in chain], ollama_models=self._ollama_models,
                    pseudonymize=config.LLM_PSEUDONYMIZE, note=None if active else (self.last_error or "No model configured: reports use the deterministic template."))

    # ------------------------------------------------------------ completion
    def _cache_path(self, key: str):
        d = config.CACHE_DIR / "llm"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{key}.json"

    def _call(self, p: dict[str, str], system: str, user: str, max_tokens: int) -> str:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        if p["kind"] == "ollama":
            r = httpx.post(f"{p['base']}/api/chat", timeout=config.LLM_TIMEOUT_S,
                           json=dict(model=p["model"], messages=messages, stream=False, options=dict(temperature=0.1, num_predict=max_tokens)))
            r.raise_for_status()
            return r.json()["message"]["content"]
        r = httpx.post(f"{p['base']}/chat/completions", timeout=config.LLM_TIMEOUT_S, headers={"Authorization": f"Bearer {p['key']}"},
                       json=dict(model=p["model"], messages=messages, temperature=0.1, max_tokens=max_tokens))
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def complete(self, system: str, user: str, max_tokens: int = 450) -> tuple[Optional[str], dict[str, Any]]:
        if self.mode == "off":
            return None, dict(provider=None, reason="LLM mode is off")
        errors: list[str] = []
        for p in self.chain():
            key = hashlib.sha256(json.dumps([p["kind"], p["model"], system, user, max_tokens]).encode()).hexdigest()
            path = self._cache_path(key)
            if path.exists():
                try:
                    return json.loads(path.read_text(encoding="utf-8"))["text"], dict(provider=p["name"], model=p["model"], cached=True, ms=0)
                except Exception:  # noqa: BLE001
                    pass
            for attempt in range(config.LLM_MAX_RETRIES + 1):
                t0 = time.time()
                try:
                    text = self._call(p, system, user, max_tokens)
                    path.write_text(json.dumps(dict(text=text, model=p["model"])), encoding="utf-8")
                    return text, dict(provider=p["name"], model=p["model"], cached=False, ms=int((time.time() - t0) * 1000))
                except httpx.HTTPStatusError as exc:
                    code = exc.response.status_code
                    errors.append(f"{p['name']}: HTTP {code}")
                    if code == 429 or code >= 500:
                        time.sleep(min(8, 2 ** attempt))  # exponential backoff
                        continue
                    break
                except Exception as exc:  # noqa: BLE001 - timeout, connection refused, bad JSON ...
                    errors.append(f"{p['name']}: {type(exc).__name__}")
                    break
        self.last_error = "; ".join(errors) or "no provider available"
        return None, dict(provider=None, reason=self.last_error)
