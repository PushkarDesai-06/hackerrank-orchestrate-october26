from pathlib import Path

CODE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = CODE_DIR.parent
DATASET_DIR = REPO_ROOT / "dataset"
CACHE_DIR = CODE_DIR / "cache"
OUTPUT_PATH = REPO_ROOT / "output.csv"
