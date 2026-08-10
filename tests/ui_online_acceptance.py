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
    parser = argparse.ArgumentParser(description="Live Cloudflare Pages to local-engine browser acceptance")
    parser.add_argument("--url", default="https://proxy-audit.pages.dev/")
    parser.add_argument("--screenshot", default=str(ROOT / "temp" / "ui-online-acceptance.png"))
    args = parser.parse_args()

    chrome = find_chrome()
    profile = Path(tempfile.mkdtemp(prefix="proxy-audit-online-chrome-"))
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    chrome_proc = subprocess.Popen(
        [
            str(chrome),
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--remote-allow-origins=*",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "--window-size=1536,900",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    cdp = None
    try:
        active_port_file = profile / "DevToolsActivePort"
        wait_for(active_port_file.exists, message="Chrome DevTools port")
        debug_port = int(active_port_file.read_text(encoding="utf-8").splitlines()[0])

        def page_target():
            targets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{debug_port}/json/list", timeout=2).read())
            return next((item for item in targets if item.get("type") == "page"), None)

        target = wait_for(page_target, message="Chrome page target")
        cdp = CDP(target["webSocketDebuggerUrl"])
        cdp.call("Page.enable")
        cdp.call("Runtime.enable")
        cdp.call("Network.enable")
        cdp.call("Log.enable")
        granted_permissions = []
        for permission_name in ("loopback-network", "local-network", "local-network-access"):
            try:
                cdp.call("Browser.setPermission", {
                    "permission": {"name": permission_name},
                    "setting": "granted",
                    "origin": args.url.rstrip("/"),
                })
                granted_permissions.append(permission_name)
            except RuntimeError as error:
                if permission_name == "loopback-network":
                    raise AssertionError(f"Chrome did not accept required LNA permission: {error}") from error
        cdp.call("Page.navigate", {"url": args.url})
        wait_for(lambda: cdp.evaluate("document.readyState === 'complete'"), timeout=20, message="online page load")
        wait_for(lambda: cdp.evaluate("!document.querySelector('#onlineModeModal')?.classList.contains('hidden')"), message="online privacy modal")
        assert cdp.evaluate("document.querySelector('.brand strong').textContent") == "Proxy Audit"
        assert "不会上传到 Proxy Audit 云端" in cdp.evaluate("document.querySelector('.online-privacy-card').textContent")
        cdp.evaluate("document.querySelector('#connectLocalEngine').click()")
        try:
            wait_for(
                lambda: cdp.evaluate("document.querySelector('#healthText')?.textContent === '本地引擎已连接'"),
                timeout=20,
                message="online UI to local engine connection",
            )
        except AssertionError:
            diagnosis = cdp.evaluate("""
              (async () => {
                const result = {
                  healthText: document.querySelector('#healthText')?.textContent,
                  buttonText: document.querySelector('#connectLocalEngine')?.textContent,
                  secureContext: window.isSecureContext,
                  origin: location.origin,
                  csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content || null,
                };
                try {
                  const response = await fetch('http://127.0.0.1:8765/api/health', {targetAddressSpace:'loopback'});
                  result.fetchStatus = response.status;
                  result.fetchText = await response.text();
                } catch (error) {
                  result.fetchError = `${error.name}: ${error.message}`;
                }
                return result;
              })()
            """, await_promise=True)
            cdp.evaluate("true")
            raise AssertionError(
                f"online UI to local engine failed: {diagnosis}; "
                f"network_failures={cdp.network_failures}; logs={cdp.log_entries}; exceptions={cdp.exceptions}"
            )
        wait_for(
            lambda: cdp.evaluate("document.querySelector('#onlineModeModal').classList.contains('hidden')"),
            message="online privacy modal close after local engine initialization",
        )
        assert cdp.evaluate("document.querySelectorAll('.kernel-card').length") == 2
        cdp.evaluate("""
          document.querySelector('#nodeText').value = 'socks://online-demo.invalid:1080#Online-Privacy-Demo';
          document.querySelector('#importButton').click();
        """)
        wait_for(
            lambda: cdp.evaluate("document.querySelector('#metricImported')?.textContent === '1'"),
            message="online UI synthetic node import through local engine",
        )
        assert "Online-Privacy-Demo" in cdp.evaluate("document.querySelector('#resultBody').textContent")
        assert cdp.evaluate("document.querySelector('#resultBody .status-pending').textContent") == "待检测"
        assert not cdp.exceptions, cdp.exceptions
        cdp.screenshot(Path(args.screenshot))
        print(json.dumps({
            "status": "passed",
            "url": args.url,
            "localEngine": "connected",
            "grantedPermissions": granted_permissions,
            "privacyModal": "passed",
            "syntheticImport": "passed",
            "javascriptExceptions": 0,
            "screenshot": str(Path(args.screenshot)),
        }, ensure_ascii=False))
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
