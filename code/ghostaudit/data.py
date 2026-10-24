"""CSV loaders for the participant-facing dataset."""
import csv
from dataclasses import dataclass, field
from pathlib import Path

from .paths import DATASET_DIR


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@dataclass
class Dataset:
    root: Path
    requests: list[dict]
    identities: dict[str, dict]
    audit_log: list[dict]
    activity: list[dict]
    rules: list[dict]
    manifest: list[dict]
    activity_by_id: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path = DATASET_DIR, requests_file: str = "deletion_requests.csv") -> "Dataset":
        activity = read_csv(root / "system_activity.csv")
        return cls(
            root=root,
            requests=read_csv(root / requests_file),
            identities={r["user_id"]: r for r in read_csv(root / "user_identities.csv")},
            audit_log=read_csv(root / "user_audit_log.csv"),
            activity=activity,
            rules=read_csv(root / "deletion_rules.csv"),
            manifest=read_csv(root / "evidence_files.csv"),
            activity_by_id={a["activity_id"]: a for a in activity},
        )
