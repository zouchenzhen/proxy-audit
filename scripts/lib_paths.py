from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "bin"
INPUT_DIR = ROOT / "input"
RESULT_DIR = ROOT / "results"
RESULT_RAW = RESULT_DIR / "raw"
RESULT_CSV = RESULT_DIR / "csv"
RESULT_REPORT = RESULT_DIR / "reports"
TEMP_DIR = ROOT / "temp"
CONFIG_DIR = TEMP_DIR / "configs"
LOG_DIR = TEMP_DIR / "logs"
UPLOAD_DIR = INPUT_DIR / "uploads"
WEB_DIR = ROOT / "web"


def ensure_project_dirs() -> None:
    for path in (
        BIN_DIR,
        INPUT_DIR,
        RESULT_RAW,
        RESULT_CSV,
        RESULT_REPORT,
        CONFIG_DIR,
        LOG_DIR,
        UPLOAD_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
