"""Summarize LLM token usage and estimated cost for a run, per model and overall."""
import json
from pathlib import Path

from .llm import OPENROUTER_PRICES, PRICES, GeminiClient


def _model_summary(client: GeminiClient, requests: int, fallback: bool = False) -> dict:
    u = client.fallback_usage if fallback else client.usage
    if fallback:
        price_in, price_out = OPENROUTER_PRICES.get(client.openrouter_model, PRICES.get(client.model, (0.0, 0.0)))
    else:
        price_in, price_out = PRICES.get(client.model, (0.0, 0.0))
    billed_out = u.output_tokens + u.thinking_tokens
    cost = u.input_tokens / 1e6 * price_in + billed_out / 1e6 * price_out
    total = u.input_tokens + billed_out
    return {
        "provider": "OpenRouter" if fallback else "Google Gemini API",
        "model": client.openrouter_model if fallback else client.model,
        "thinking_level": client.thinking_level,
        "served_models": sorted(u.served_models),
        "price_per_million_usd": {"input": price_in, "output": price_out},
        "model_calls": u.calls,
        "calls_served_from_cache": u.cached_calls,
        "input_tokens": u.input_tokens,
        "output_tokens": u.output_tokens,
        "thinking_tokens": u.thinking_tokens,
        "total_tokens": total,
        "avg_tokens_per_request": total / requests if requests else 0,
        "estimated_cost_usd": round(cost, 6),
        "estimated_cost_per_request_usd": round(cost / requests, 8) if requests else 0,
        "by_purpose": u.by_purpose,
    }


def summarize(clients: list[GeminiClient], requests: int) -> dict:
    models = [_model_summary(c, requests) for c in clients]
    models += [_model_summary(c, requests, fallback=True) for c in clients if c.fallback_usage.calls]
    keys = ["model_calls", "calls_served_from_cache", "input_tokens", "output_tokens", "thinking_tokens",
            "total_tokens", "estimated_cost_usd"]
    overall = {k: sum(m[k] for m in models) for k in keys}
    overall["estimated_cost_usd"] = round(overall["estimated_cost_usd"], 6)
    overall["avg_tokens_per_request"] = overall["total_tokens"] / requests if requests else 0
    overall["estimated_cost_per_request_usd"] = round(overall["estimated_cost_usd"] / requests, 8) if requests else 0
    return {"requests_audited": requests, "models": models, "overall": overall}


def write_usage(clients: list[GeminiClient], requests: int, path: Path) -> dict:
    data = summarize(clients, requests)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data
