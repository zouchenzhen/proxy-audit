"""Live Hugging Face browser smoke test using an isolated Chrome profile.

The test creates and deletes an empty anonymous session. It never uploads a
node, subscription, API key, or result and never touches the normal profile.
"""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from ui_browser_acceptance import CDP, find_chrome, wait_for


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Live Hugging Face cloud-session browser smoke test")
    parser.add_argument("--url", default="https://zouchenzhen-zcz.hf.space/")
    parser.add_argument("--screenshot", default=str(ROOT / "temp" / "ui-online-acceptance.png"))
    args = parser.parse_args()

    chrome = find_chrome()
    profile = Path(tempfile.mkdtemp(prefix="proxy-audit-online-chrome-"))
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    chrome_proc = subprocess.Popen([
        str(chrome), "--headless=new", "--disable-gpu", "--no-first-run",
        "--no-default-browser-check", "--remote-allow-origins=*", "--remote-debugging-port=0",
        f"--user-data-dir={profile}", "--window-size=1536,900", "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)
    cdp = None
    try:
        active_port_file = profile / "DevToolsActivePort"
        wait_for(active_port_file.exists, message="Chrome DevTools port")
        debug_port = int(active_port_file.read_text(encoding="utf-8").splitlines()[0])
        targets = lambda: json.loads(urllib.request.urlopen(f"http://127.0.0.1:{debug_port}/json/list", timeout=2).read())
        target = wait_for(lambda: next((item for item in targets() if item.get("type") == "page"), None), message="Chrome page target")
        cdp = CDP(target["webSocketDebuggerUrl"])
        for domain in ("Page", "Runtime", "Network", "Log"):
            cdp.call(f"{domain}.enable")
        cdp.call("Page.navigate", {"url": args.url})
        wait_for(lambda: cdp.evaluate("document.readyState === 'complete'"), timeout=60, message="online page load")
        wait_for(lambda: cdp.evaluate("!document.querySelector('#onlineModeModal')?.classList.contains('hidden')"), timeout=30, message="cloud privacy modal")
        modal = cdp.evaluate("document.querySelector('.online-mode-modal').textContent")
        assert "上传到临时云端后端" in modal and "最长 12 秒" in modal
        cdp.evaluate("document.querySelector('#startCloudSession').click()")
        wait_for(lambda: cdp.evaluate("document.querySelector('#healthText')?.textContent.includes('云端临时会话已连接')"), timeout=60, message="anonymous cloud session")
        assert cdp.evaluate("document.querySelectorAll('.kernel-card').length") == 2
        cdp.screenshot(Path(args.screenshot))
        cdp.evaluate("document.querySelector('#deleteCloudSession').click()")
        wait_for(lambda: cdp.evaluate("sessionStorage.getItem('proxyAudit.cloudSession') === null"), message="session deletion")
        assert not cdp.exceptions, cdp.exceptions
        print(json.dumps({"status": "passed", "url": args.url, "emptySession": "created-and-deleted", "javascriptExceptions": 0, "screenshot": args.screenshot}))
    finally:
        if cdp:
            try:
                cdp.close()
            except Exception:
                pass
        if chrome_proc.poll() is None:
            chrome_proc.terminate()
            try:
                chrome_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                chrome_proc.kill()
        for _ in range(20):
            try:
                shutil.rmtree(profile)
                break
            except OSError:
                time.sleep(0.1)


if __name__ == "__main__":
    main()
