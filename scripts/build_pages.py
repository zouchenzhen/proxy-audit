import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web"
DIST_DIR = ROOT / "pages-dist"


def main() -> None:
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    (DIST_DIR / "static").mkdir(parents=True)
    shutil.copy2(WEB_DIR / "index.html", DIST_DIR / "index.html")
    shutil.copy2(WEB_DIR / "legal.html", DIST_DIR / "legal.html")
    shutil.copy2(WEB_DIR / "styles.css", DIST_DIR / "static" / "styles.css")
    shutil.copy2(WEB_DIR / "app.js", DIST_DIR / "static" / "app.js")
    shutil.copy2(ROOT / "cloudflare" / "_headers", DIST_DIR / "_headers")
    print(f"Cloudflare Pages bundle created: {DIST_DIR}")


if __name__ == "__main__":
    main()
