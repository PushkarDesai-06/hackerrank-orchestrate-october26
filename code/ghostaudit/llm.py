"""Minimal Gemini REST client with a disk cache and token accounting.

Only the standard library is used. API keys are read from the environment
(GEMINI_API_KEYS as a comma-separated list, and/or GEMINI_API_KEY), optionally
loaded from a local .env file. Requests rotate across the keys round robin,
starting at a random key, and fail over to the next key on timeouts or rate limits.
If every Gemini key fails, OPENROUTER_API_KEY is used as the last fallback.
Every response is cached by a hash of its request, so reruns cost nothing and
stay deterministic.
"""
import base64
import hashlib
import json
import os
import random
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .paths import CACHE_DIR, REPO_ROOT

API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
# Screens and documents need careful reading; request texts are a short routing task.
DEFAULT_VISION_MODEL = "gemini-3.6-flash"
DEFAULT_TEXT_MODEL = "gemini-3.5-flash-lite"
# USD per million tokens (input, output) from ai.google.dev pricing. Thinking tokens bill as output.
PRICES = {
    "gemini-3.6-flash": (1.50, 7.50),
    "gemini-3.5-flash-lite": (0.30, 2.50),
    "gemini-2.5-flash": (0.30, 2.50),
}
# OpenRouter list prices for the same models (from openrouter.ai/api/v1/models).
OPENROUTER_PRICES = {
    "google/gemini-3.6-flash": (0.75, 3.75),
    "google/gemini-3.5-flash-lite": (0.30, 2.50),
    "openrouter/free": (0.0, 0.0),
}


def load_dotenv(path: Path = REPO_ROOT / ".env") -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


@dataclass
class Usage:
    served_models: set = field(default_factory=set)
    calls: int = 0
    cached_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    thinking_tokens: int = 0
    by_purpose: dict = field(default_factory=dict)

    def add(self, purpose: str, meta: dict, cached: bool):
        p = self.by_purpose.setdefault(purpose, {"calls": 0, "cached_calls": 0, "input_tokens": 0,
                                                 "output_tokens": 0, "thinking_tokens": 0})
        inp = int(meta.get("promptTokenCount", 0))
        out = int(meta.get("candidatesTokenCount", 0))
        think = int(meta.get("thoughtsTokenCount", 0))
        if meta.get("servedModel"):
            self.served_models.add(meta["servedModel"])
        for target in (self, p):
            if isinstance(target, Usage):
                target.calls += 1
                target.cached_calls += int(cached)
                target.input_tokens += inp
                target.output_tokens += out
                target.thinking_tokens += think
            else:
                target["calls"] += 1
                target["cached_calls"] += int(cached)
                target["input_tokens"] += inp
                target["output_tokens"] += out
                target["thinking_tokens"] += think


REQUEST_TIMEOUT = 120


def _parse_json(text: str):
    """Parse a model reply, tolerating code fences or prose around one JSON object."""
    if not text:
        return None
    candidate = _strip_fences(text)
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        start, end = candidate.find("{"), candidate.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(candidate[start:end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t
        t = t.rsplit("```", 1)[0]
    return t.strip()
RETRYABLE = {408, 429, 500, 502, 503, 504}


def load_keys() -> list[str]:
    """Keys from GEMINI_API_KEYS (comma separated) plus GEMINI_API_KEY / GOOGLE_API_KEY."""
    raw = os.environ.get("GEMINI_API_KEYS", "").split(",")
    raw += [os.environ.get("GEMINI_API_KEY", ""), os.environ.get("GOOGLE_API_KEY", "")]
    keys: list[str] = []
    for k in (x.strip() for x in raw):
        if k and k not in keys:
            keys.append(k)
    return keys


def vision_client() -> "GeminiClient":
    load_dotenv()
    return GeminiClient(os.environ.get("GEMINI_VISION_MODEL", DEFAULT_VISION_MODEL),
                        os.environ.get("GEMINI_VISION_THINKING", "medium"))


def text_client() -> "GeminiClient":
    load_dotenv()
    return GeminiClient(os.environ.get("GEMINI_TEXT_MODEL", DEFAULT_TEXT_MODEL),
                        os.environ.get("GEMINI_TEXT_THINKING", "minimal"))


class GeminiClient:
    def __init__(self, model: str, thinking_level: str | None = None, cache_dir: Path = CACHE_DIR / "llm"):
        load_dotenv()
        self.model = model
        self.thinking_level = thinking_level
        self.keys = load_keys()
        # Last resort when every Gemini key fails: the same model through OpenRouter.
        self.openrouter_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        self.openrouter_model = os.environ.get(
            "OPENROUTER_VISION_MODEL" if thinking_level == "medium" else "OPENROUTER_TEXT_MODEL", f"google/{model}")
        self.fallback_usage = Usage()
        # "auto": Gemini keys first, OpenRouter last; "openrouter" or "gemini" forces one route.
        self.provider = os.environ.get("LLM_PROVIDER", "auto").strip().lower()
        # Start at a random key so parallel or repeated runs do not all hammer the first one.
        self._next = random.randrange(len(self.keys)) if self.keys else 0
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.usage = Usage()

    @property
    def available(self) -> bool:
        if self.provider == "openrouter":
            return bool(self.openrouter_key)
        if self.provider == "gemini":
            return bool(self.keys)
        return bool(self.keys or self.openrouter_key)

    def _take_key(self) -> str:
        """Round robin: every request (and every retry) moves to the next key."""
        key = self.keys[self._next % len(self.keys)]
        self._next = (self._next + 1) % len(self.keys)
        return key

    def _cache_path(self, payload: dict) -> Path:
        digest = hashlib.sha256(json.dumps({"model": self.model, "payload": payload},
                                           sort_keys=True).encode()).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def generate_json(self, purpose: str, prompt: str, attachment: Path | None = None,
                      mime_type: str | None = None, schema: dict | None = None):
        """Send one prompt (plus optional file) and return the parsed JSON reply."""
        parts: list[dict] = [{"text": prompt}]
        if attachment is not None:
            parts.append({"inline_data": {"mime_type": mime_type,
                                          "data": base64.b64encode(attachment.read_bytes()).decode()}})
        # Gemini 3 ignores sampling parameters; determinism comes from the cache.
        config: dict = {"responseMimeType": "application/json"}
        if self.thinking_level:
            config["thinkingConfig"] = {"thinkingLevel": self.thinking_level}
        if schema:
            config["responseSchema"] = schema
        payload = {"contents": [{"role": "user", "parts": parts}], "generationConfig": config}
        # Cache key uses a digest of the attachment instead of its bytes.
        key_payload = dict(payload)
        if attachment is not None:
            key_payload = {"prompt": prompt, "file_sha256": hashlib.sha256(attachment.read_bytes()).hexdigest(),
                           "config": config}
        cache = self._cache_path(key_payload)
        if cache.exists():
            record = json.loads(cache.read_text(encoding="utf-8"))
            target = self.fallback_usage if record.get("provider") == "openrouter" else self.usage
            target.add(purpose, record.get("usage", {}), cached=True)
            return record["result"]
        if not self.available:
            raise RuntimeError("no Gemini or OpenRouter key is set and no cached response exists")
        provider, text, usage = "gemini", None, {}
        gemini_error = ""
        if self.keys and self.provider != "openrouter":
            try:
                body = self._post(payload)
                text = "".join(p.get("text", "") for p in body["candidates"][0]["content"]["parts"])
                usage = body.get("usageMetadata", {})
            except (RuntimeError, KeyError, IndexError) as exc:
                gemini_error = str(exc)
        result = _parse_json(text) if text is not None else None
        if result is None:
            if not self.openrouter_key or self.provider == "gemini":
                raise RuntimeError(gemini_error or "Gemini returned no usable JSON")
            provider = "openrouter"
            # Router models vary per call, so retry when a reply is not usable JSON.
            for _ in range(3):
                text, usage = self._post_openrouter(parts)
                result = _parse_json(text)
                if result is not None:
                    break
                self.fallback_usage.add(purpose, usage, cached=False)
            if result is None:
                raise RuntimeError(f"OpenRouter returned no usable JSON: {text[:120]!r}")
        cache.write_text(json.dumps({"model": self.model if provider == "gemini" else self.openrouter_model,
                                     "provider": provider, "purpose": purpose, "usage": usage, "result": result},
                                    indent=1, ensure_ascii=False), encoding="utf-8")
        (self.usage if provider == "gemini" else self.fallback_usage).add(purpose, usage, cached=False)
        return result

    def _post_openrouter(self, parts: list[dict]) -> tuple[str, dict]:
        """Send the same prompt through OpenRouter's OpenAI-style chat API."""
        content = []
        for part in parts:
            if "text" in part:
                content.append({"type": "text", "text": part["text"] + "\nRespond with a single JSON object only, "
                                "no prose and no code fences."})
            else:
                inline = part["inline_data"]
                url = f"data:{inline['mime_type']};base64,{inline['data']}"
                if inline["mime_type"] == "application/pdf":
                    content.append({"type": "file", "file": {"filename": "evidence.pdf", "file_data": url}})
                else:
                    content.append({"type": "image_url", "image_url": {"url": url}})
        body = {"model": self.openrouter_model, "messages": [{"role": "user", "content": content}],
                "response_format": {"type": "json_object"}}
        req = urllib.request.Request(OPENROUTER_URL, data=json.dumps(body).encode(), method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {self.openrouter_key}"})
        last_error = ""
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                    data = json.loads(resp.read())
                text = data["choices"][0]["message"]["content"]
                u = data.get("usage", {})
                reasoning = int((u.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0)
                # Store usage in Gemini's field names so accounting stays uniform.
                return text, {"promptTokenCount": u.get("prompt_tokens", 0),
                              "candidatesTokenCount": int(u.get("completion_tokens", 0)) - reasoning,
                              "thoughtsTokenCount": reasoning,
                              # A router id such as openrouter/free resolves to a concrete model.
                              "servedModel": data.get("model", self.openrouter_model)}
            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code}: {e.read()[:200]!r}"
                if e.code not in RETRYABLE:
                    break
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, KeyError) as e:
                last_error = f"{type(e).__name__}: {e}"
            time.sleep(5 * 2 ** attempt)
        raise RuntimeError(f"OpenRouter fallback failed: {last_error}")

    def _post(self, payload: dict, rounds: int = 3) -> dict:
        """POST with key rotation: a timeout, 429 or 5xx moves straight to the next key;
        once every key has failed in a round, back off before the next round."""
        data = json.dumps(payload).encode()
        last_error = ""
        for round_no in range(rounds):
            for _ in range(len(self.keys)):
                req = urllib.request.Request(
                    API_URL.format(model=self.model), data=data, method="POST",
                    headers={"Content-Type": "application/json", "x-goog-api-key": self._take_key()})
                try:
                    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                        return json.loads(resp.read())
                except urllib.error.HTTPError as e:
                    last_error = f"HTTP {e.code}: {e.read()[:200]!r}"
                    if e.code not in RETRYABLE:
                        raise RuntimeError(f"Gemini API error {last_error}") from None
                except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
                    last_error = f"{type(e).__name__}: {e}"
            if round_no + 1 < rounds:
                time.sleep(5 * 2 ** round_no)
        raise RuntimeError(f"Gemini API failed on all {len(self.keys)} key(s): {last_error}")
