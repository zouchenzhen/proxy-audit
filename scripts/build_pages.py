import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "pages-dist"


def main() -> None:
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True)
    shutil.copy2(ROOT / "cloudflare" / "_headers", DIST_DIR / "_headers")
    shutil.copy2(ROOT / "cloudflare" / "_redirects", DIST_DIR / "_redirects")
    print(f"Cloudflare Pages redirect bundle created: {DIST_DIR}")


if __name__ == "__main__":
    main()
