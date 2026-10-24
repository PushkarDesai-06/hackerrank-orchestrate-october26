"""End-to-end run: classify, extract evidence, audit every case, serialize."""
import csv
import json
from dataclasses import dataclass
from pathlib import Path

from .auditor import Auditor
from .classify import classify_requests
from .data import Dataset, read_csv
from .evidence import load_observations
from .llm import GeminiClient, text_client, vision_client
from .vision import VisionExtractor


@dataclass
class RunResult:
    rows: list[dict]
    auditor: Auditor
    clients: list[GeminiClient]
    notes: list[str]
    non_deletion: set


def run(dataset: Dataset, use_llm: bool = True, extra_requests: list[dict] | None = None) -> RunResult:
    """Audit dataset.requests. `extra_requests` share the timeline (for linking) but get no row."""
    # Without an API key the cache can still answer; misses fall back to rules.
    text = text_client() if use_llm else None
    vision = vision_client() if use_llm else None
    timeline = list(dataset.requests) + list(extra_requests or [])
    decisions, notes = classify_requests([r["request_text"] for r in timeline], text)
    non_deletion = {r["case_id"] for r in timeline if not decisions[r["request_text"]]}
    extractor = VisionExtractor(vision) if vision is not None else None
    observations, coverage = load_observations(dataset.root, dataset.manifest, extractor)
    if extractor is not None:
        notes.extend(extractor.errors)
    auditor = Auditor(dataset, observations, coverage, timeline, non_deletion)
    rows = []
    for req in sorted(dataset.requests, key=lambda r: case_sort_key(r["case_id"])):
        cid = req["case_id"]
        if cid in non_deletion:
            rows.append({"case_id": cid, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"})
            continue
        status, steps, _ = auditor.plan(cid)
        rows.append({"case_id": cid, "deletion_status": status,
                     "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False)})
    clients = [c for c in (text, vision) if c is not None]
    return RunResult(rows=rows, auditor=auditor, clients=clients, notes=notes, non_deletion=non_deletion)


def case_sort_key(case_id: str):
    """Sort case ids by their number (case_2 before case_10), falling back to text."""
    prefix, _, num = case_id.rpartition("_")
    return (prefix, int(num)) if num.isdigit() else (case_id, 0)


def write_output(rows: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"])
        w.writeheader()
        w.writerows(rows)


def validate_rows(rows: list[dict], requests: list[dict]) -> list[str]:
    """Contract checks on the output before it is written."""
    problems = []
    if len(rows) != len(requests):
        problems.append(f"row count {len(rows)} != request count {len(requests)}")
    if {r["case_id"] for r in rows} != {r["case_id"] for r in requests}:
        problems.append("case ids differ from deletion_requests.csv")
    allowed = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    for r in rows:
        steps = json.loads(r["steps_json"])
        if r["deletion_status"] not in allowed:
            problems.append(f"{r['case_id']}: bad status {r['deletion_status']}")
        if r["deletion_status"] == "NOT_APPLICABLE" and steps:
            problems.append(f"{r['case_id']}: NOT_APPLICABLE with steps")
        if [s["step_no"] for s in steps] != list(range(1, len(steps) + 1)):
            problems.append(f"{r['case_id']}: step numbers not consecutive")
        phases = [s["phase"] for s in steps]
        order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        if phases != sorted(phases, key=order.get):
            problems.append(f"{r['case_id']}: phases out of order")
        for s in steps:
            if r["deletion_status"] == "INCOMPLETE" and s["phase"] != "FINDING" and s["evidence_id"]:
                problems.append(f"{r['case_id']}: future step cites evidence")
            if (s["phase"] == "FINDING" or r["deletion_status"] == "COMPLETE") and not s["evidence_id"]:
                problems.append(f"{r['case_id']}: step {s['step_no']} lacks evidence")
    return problems


def load_extra_requests(dataset: Dataset) -> list[dict]:
    """The public sample requests share the platform timeline with the evaluation set."""
    path = dataset.root / "sample_deletion_requests.csv"
    return read_csv(path) if path.exists() else []
