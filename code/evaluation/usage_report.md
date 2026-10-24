# Usage Report: Final Full-Dataset Run

Author: Pushkar Desai (2024eb02433)

This covers the run of `python3 code/main.py` that produced the submitted `output.csv` (518 requests).
Every model response is cached under `code/cache/llm/`; the final invocation was served entirely from that
cache, and the token counts below are the counts recorded by the API when each response was first produced.
Machine-readable totals: `code/evaluation/last_run_usage.json`.

## What the models were used for

| Purpose | Calls | Notes |
| --- | --- | --- |
| Request classification | 16 | 375 distinct request texts (plus the 32 sample texts) in batches of 25. |
| Evidence extraction | 15 | One call per screenshot (11) and PDF (4). |
| Everything else | 0 | Parsing, identity resolution, linking, policy and planning are deterministic code. |

## Per model

| Provider | Model | Calls | Input tokens | Output tokens | Thinking tokens | Total tokens | Price (USD per 1M in / out) | Est. cost (USD) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Google Gemini API | gemini-3.5-flash-lite (thinking minimal) | 16 | 17,552 | 13,585 | 0 | 31,137 | 0.30 / 2.50 | 0.039228 |
| Google Gemini API | gemini-3.6-flash (thinking medium) | 8 | 12,852 | 3,695 | 18,991 | 35,538 | 1.50 / 7.50 | 0.189423 |
| OpenRouter | openrouter/free (served by dots-studio/dots-3-note-preview, nvidia/nemotron-3-ultra-550b-a55b, nvidia/nemotron-3.5-super-vl, recursive/flint-v1.0, all `:free`) | 7 | 11,221 | 6,589 | 31,194 | 49,004 | 0.00 / 0.00 | 0.000000 |

Thinking tokens are billed as output tokens and are included in "Total tokens" and cost.

## Overall

| Item | Value |
| --- | --- |
| Model calls | 31 |
| Input tokens | 41,625 |
| Output tokens | 23,869 |
| Thinking tokens | 50,185 |
| Total tokens | 115,679 |
| Average tokens per request (518) | 223.3 |
| Estimated total cost | **USD 0.2287** |
| Estimated cost per request | **USD 0.00044** |

## Notes

- Calls that failed before returning a result are not in the totals because they returned no usage:
  7 Gemini extraction calls hit HTTP 503 (high demand) or 429 (quota).
- The live OpenRouter pass made 10 calls in total: the 7 cached replies above plus 3 retries whose
  replies were not usable JSON (14,935 input tokens over all 10 calls). All went to free models, so the
  cost is unchanged at USD 0.
- One development smoke-test extraction and one classification batch made by the evaluation harness for
  the custom cases are outside this run.
- Prices: Gemini rates from ai.google.dev pricing; OpenRouter `openrouter/free` routes only to free models.
- Cost control: deterministic code handles the 518 cases; the model is used for 31 calls in total, results
  are cached, and keys rotate round robin with OpenRouter as the last fallback.
