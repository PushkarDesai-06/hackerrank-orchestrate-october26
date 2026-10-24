"""Score the agent on the public samples and on the custom cases.

Usage:
    python3 code/evaluation/main.py            # uses Gemini cache / API when available
    python3 code/evaluation/main.py --no-llm   # rules only
Writes code/evaluation/last_eval.json with all metrics and per-case diffs.
"""
import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE))

from evaluation.custom_cases import build  # noqa: E402
from evaluation.metrics import rows_to_map, score, step_key  # noqa: E402
from ghostaudit.data import Dataset, read_csv  # noqa: E402
from ghostaudit.pipeline import run  # noqa: E402


def diff(pred: dict, gold: dict) -> list[dict]:
    out = []
    for cid in gold:
        g, p = gold[cid], pred.get(cid, {"deletion_status": "", "steps": []})
        gk = [step_key(s) for s in g["steps"]]
        pk = [step_key(s) for s in p["steps"]]
        if gk == pk and g["deletion_status"] == p["deletion_status"]:
            continue
        out.append({"case_id": cid, "gold_status": g["deletion_status"], "pred_status": p["deletion_status"],
                    "missing": [list(k) for k in gk if k not in pk],
                    "extra": [list(k) for k in pk if k not in gk]})
    return out


def evaluate_samples(use_llm: bool) -> dict:
    ds = Dataset.load(requests_file="sample_deletion_requests.csv")
    # The evaluation requests share the same platform timeline; include them so
    # overlapping workflow runs are attributed the same way as in the real run.
    timeline = read_csv(ds.root / "deletion_requests.csv")
    result = run(ds, use_llm=use_llm, extra_requests=timeline)
    pred = rows_to_map(result.rows)
    gold = rows_to_map(read_csv(ds.root / "sample_output.csv"))
    return {"metrics": score(pred, gold), "diffs": diff(pred, gold)}


def evaluate_custom(use_llm: bool) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = build(Path(tmp))
        ds = Dataset.load(root=root)
        result = run(ds, use_llm=use_llm)
        pred = rows_to_map(result.rows)
        gold = rows_to_map(read_csv(root / "expected_output.csv"))
    return {"metrics": score(pred, gold), "diffs": diff(pred, gold)}


def show(name: str, res: dict) -> None:
    m = res["metrics"]
    print(f"== {name}: {m['cases']} cases")
    print(f"   status accuracy   {m['status_accuracy']:.3f}")
    print(f"   step precision    {m['step_precision']:.3f}  recall {m['step_recall']:.3f}  F1 {m['step_f1']:.3f}")
    print(f"   field accuracy    {m['field_accuracy_overall']:.3f}  "
          + " ".join(f"{k}={v:.3f}" for k, v in m["field_accuracy"].items()))
    print(f"   sequence accuracy {m['sequence_accuracy']:.3f}")
    for d in res["diffs"]:
        print(f"   - {d['case_id']}: gold={d['gold_status']} pred={d['pred_status']} "
              f"missing={len(d['missing'])} extra={len(d['extra'])}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--provider", choices=["auto", "gemini", "openrouter"])
    args = ap.parse_args()
    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider
    use_llm = not args.no_llm
    report = {"samples": evaluate_samples(use_llm), "custom": evaluate_custom(use_llm)}
    show("public samples", report["samples"])
    show("custom cases", report["custom"])
    (CODE / "evaluation" / "last_eval.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
