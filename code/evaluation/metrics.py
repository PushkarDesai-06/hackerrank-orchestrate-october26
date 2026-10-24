"""Scoring helpers that compare predicted rows with reference rows."""
import json
from collections import Counter

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def step_key(s: dict) -> tuple:
    return tuple(str(s.get(f, "")) for f in FIELDS)


def score(pred: dict[str, dict], gold: dict[str, dict]) -> dict:
    """pred/gold: case_id -> {"deletion_status": str, "steps": list[dict]}"""
    n = len(gold)
    status_ok = 0
    tp = fp = fn = 0
    field_hits = Counter()
    field_total = 0
    seq_ok = 0
    failures = []
    for cid, g in gold.items():
        p = pred.get(cid, {"deletion_status": "", "steps": []})
        if p["deletion_status"] == g["deletion_status"]:
            status_ok += 1
        gk = Counter(step_key(s) for s in g["steps"])
        pk = Counter(step_key(s) for s in p["steps"])
        inter = sum((gk & pk).values())
        tp += inter
        fp += sum(pk.values()) - inter
        fn += sum(gk.values()) - inter
        # Field accuracy aligns steps by position, which also reflects ordering.
        for i, gs in enumerate(g["steps"]):
            field_total += 1
            ps = p["steps"][i] if i < len(p["steps"]) else {}
            for f in FIELDS:
                if str(ps.get(f, "")) == str(gs.get(f, "")):
                    field_hits[f] += 1
        exact = [step_key(s) for s in p["steps"]] == [step_key(s) for s in g["steps"]]
        if exact and p["deletion_status"] == g["deletion_status"]:
            seq_ok += 1
        else:
            failures.append(cid)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "cases": n,
        "status_accuracy": status_ok / n if n else 0.0,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "field_accuracy": {f: field_hits[f] / field_total for f in FIELDS} if field_total else {},
        "field_accuracy_overall": sum(field_hits.values()) / (field_total * len(FIELDS)) if field_total else 0.0,
        "sequence_accuracy": seq_ok / n if n else 0.0,
        "failures": failures,
    }


def rows_to_map(rows: list[dict]) -> dict[str, dict]:
    return {r["case_id"]: {"deletion_status": r["deletion_status"], "steps": json.loads(r["steps_json"] or "[]")}
            for r in rows}
