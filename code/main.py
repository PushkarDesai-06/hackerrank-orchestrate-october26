"""Ghost Data Still Exists: audit every deletion request and write output.csv.

Usage:
    python3 code/main.py                 # full run, writes ./output.csv
    python3 code/main.py --no-llm        # rules only (no Gemini calls, no image/PDF reading)
    python3 code/main.py --out path.csv  # write somewhere else
    python3 code/main.py --provider openrouter   # send uncached calls to OpenRouter only
"""
import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghostaudit.data import Dataset  # noqa: E402
from ghostaudit.paths import CODE_DIR, OUTPUT_PATH  # noqa: E402
from ghostaudit.pipeline import load_extra_requests, run, validate_rows, write_output  # noqa: E402
from ghostaudit.usage import write_usage  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-llm", action="store_true", help="skip Gemini (rule-based classification, no images)")
    ap.add_argument("--out", type=Path, default=OUTPUT_PATH)
    ap.add_argument("--provider", choices=["auto", "gemini", "openrouter"],
                    help="LLM route: Gemini keys then OpenRouter (auto), or force one")
    args = ap.parse_args()
    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider

    dataset = Dataset.load()
    extra = load_extra_requests(dataset)
    result = run(dataset, use_llm=not args.no_llm, extra_requests=extra)
    problems = validate_rows(result.rows, dataset.requests)
    if problems:
        print("Output validation failed:", *problems[:20], sep="\n  ")
        return 1
    write_output(result.rows, args.out)

    counts = Counter(r["deletion_status"] for r in result.rows)
    steps = sum(len(json.loads(r["steps_json"])) for r in result.rows)
    print(f"Wrote {len(result.rows)} rows to {args.out}")
    print("Status counts:", dict(counts), f"| total steps: {steps}")
    for note in result.notes:
        print("note:", note)
    if result.clients:
        usage_path = CODE_DIR / "evaluation" / "last_run_usage.json"
        write_usage(result.clients, len(result.rows), usage_path)
        for c in result.clients:
            u = c.usage
            print(f"LLM {c.model}: calls={u.calls} (cached {u.cached_calls}) "
                  f"input={u.input_tokens} output={u.output_tokens} thinking={u.thinking_tokens}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
