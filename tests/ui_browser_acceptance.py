import argparse
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import websocket


ROOT = Path(__file__).resolve().parents[1]
RUN_ID_PATTERN = re.compile(r"^\d{8}_\d{6}_[0-9a-f]{6}$")


def cleanup_acceptance_run(task_id: str | None) -> None:
    if not task_id or not RUN_ID_PATTERN.fullmatch(task_id):
        return
    for path in (
        ROOT / "results" / "raw" / f"run_{task_id}.json",
        ROOT / "results" / "csv" / f"run_{task_id}.csv",
        ROOT / "results" / "reports" / f"run_{task_id}.md",
    ):
        path.unlink(missing_ok=True)


def find_chrome() -> Path:
    candidates = [
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    located = shutil.which("chrome") or shutil.which("msedge")
    if located:
        return Path(located)
    raise RuntimeError("Chrome or Edge was not found")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for(predicate, timeout=12.0, interval=0.1, message="condition"):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception as exc:
            last = exc
        time.sleep(interval)
    raise AssertionError(f"Timed out waiting for {message}: {last}")


class CDP:
    def __init__(self, url: str):
        self.ws = websocket.create_connection(url, timeout=8, origin="http://localhost")
        self.next_id = 0
        self.exceptions = []
        self.network_failures = []
        self.log_entries = []

    def call(self, method, params=None):
        self.next_id += 1
        call_id = self.next_id
        self.ws.send(json.dumps({"id": call_id, "method": method, "params": params or {}}))
        while True:
            message = json.loads(self.ws.recv())
            if message.get("method") == "Runtime.exceptionThrown":
                details = message.get("params", {}).get("exceptionDetails", {})
                self.exceptions.append(details.get("text") or "JavaScript exception")
            if message.get("method") == "Network.loadingFailed":
                params = message.get("params", {})
                self.network_failures.append({
                    "errorText": params.get("errorText"),
                    "blockedReason": params.get("blockedReason"),
                    "corsErrorStatus": params.get("corsErrorStatus"),
                })
            if message.get("method") == "Log.entryAdded":
                entry = message.get("params", {}).get("entry", {})
                self.log_entries.append({"level": entry.get("level"), "text": entry.get("text")})
            if message.get("id") == call_id:
                if "error" in message:
                    raise RuntimeError(f"CDP {method}: {message['error']}")
                return message.get("result") or {}

    def evaluate(self, expression, await_promise=False):
        result = self.call("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": await_promise,
        })
        if result.get("exceptionDetails"):
            raise AssertionError(result["exceptionDetails"])
        return (result.get("result") or {}).get("value")

    def screenshot(self, path: Path):
        result = self.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(result["data"]))

    def close(self):
        self.ws.close()


def main():
    parser = argparse.ArgumentParser(description="Real-browser acceptance test for Proxy Audit Web UI")
    parser.add_argument("--width", type=int, default=1536)
    parser.add_argument("--height", type=int, default=700)
    parser.add_argument("--screenshot", default=str(ROOT / "temp" / "ui-browser-acceptance.png"))
    parser.add_argument("--write-demo-assets", action="store_true", help="refresh README screenshots using synthetic .invalid nodes")
    args = parser.parse_args()

    app_port = free_port()
    chrome = find_chrome()
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    app_proc = subprocess.Popen(
        [sys.executable, "scripts/web_app.py", "--no-open", "--port", str(app_port)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    chrome_proc = None
    cdp = None
    generated_task_id = None
    summary = {}
    try:
        wait_for(
            lambda: json.loads(urllib.request.urlopen(f"http://127.0.0.1:{app_port}/api/health", timeout=1).read())["ok"],
            message="local Flask server",
        )
        profile = Path(tempfile.mkdtemp(prefix="proxy-audit-chrome-"))
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
                f"--window-size={args.width},{args.height}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
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
        cdp.call("Emulation.setDeviceMetricsOverride", {
            "width": args.width,
            "height": args.height,
            "deviceScaleFactor": 1,
            "mobile": False,
        })
        cdp.call("Page.navigate", {"url": f"http://127.0.0.1:{app_port}/"})
        wait_for(lambda: cdp.evaluate("document.readyState === 'complete'"), message="page load")
        wait_for(lambda: cdp.evaluate("document.querySelector('#healthText')?.textContent === '本地引擎已连接'"), message="system API render")
        assert cdp.evaluate("document.title") == "Proxy Audit · 节点 IP 质量审计"
        assert cdp.evaluate("document.querySelector('.brand strong').textContent") == "Proxy Audit"
        legacy_storage = cdp.evaluate("""
          (() => {
            localStorage.removeItem('proxyAudit.theme');
            localStorage.setItem('proxyScope.theme', 'dark');
            migrateLegacyStorage();
            return {
              migrated: localStorage.getItem('proxyAudit.theme'),
              legacyRemoved: localStorage.getItem('proxyScope.theme') === null,
            };
          })()
        """)
        assert legacy_storage == {"migrated": "dark", "legacyRemoved": True}, legacy_storage

        geometry = cdp.evaluate("""
          (() => {
            const rail = document.querySelector('.control-rail');
            const cards = [...document.querySelectorAll('.kernel-card')];
            const step2 = document.querySelector('[data-step="2"]');
            const dock = document.querySelector('.run-dock');
            const railRect = rail.getBoundingClientRect();
            return {
              kernelCards: cards.length,
              railHorizontalOverflow: rail.scrollWidth - rail.clientWidth,
              cardOverflow: Math.max(...cards.map(card => card.getBoundingClientRect().right - railRect.right)),
              dockOverlap: step2.getBoundingClientRect().bottom - dock.getBoundingClientRect().top,
              railScrollable: rail.scrollHeight > rail.clientHeight,
            };
          })()
        """)
        assert geometry["kernelCards"] == 2, geometry
        assert geometry["railHorizontalOverflow"] <= 1, geometry
        assert geometry["cardOverflow"] <= 1, geometry
        assert geometry["dockOverlap"] <= 1, geometry
        assert geometry["railScrollable"], geometry

        cdp.evaluate("document.querySelector('#settingsButton').click()")
        wait_for(lambda: cdp.evaluate("!document.querySelector('#settingsModal').classList.contains('hidden')"), message="settings modal")
        modal = cdp.evaluate("""
          (() => {
            const box = document.querySelector('.settings-modal').getBoundingClientRect();
            const fields = [...document.querySelectorAll('.key-field')];
            return {
              bodyLocked: document.body.classList.contains('modal-open'),
              viewportFit: box.top >= 0 && box.bottom <= innerHeight,
              fieldOverflow: fields.filter(field => {
                const rect = field.getBoundingClientRect();
                return rect.left < box.left || rect.right > box.right;
              }).length,
              clearControls: document.querySelectorAll('.clear-option').length,
              keyPoolInputs: document.querySelectorAll('.secret-entry').length,
              keyEyes: document.querySelectorAll('[data-key-eye]').length,
              keyEyeSvgs: document.querySelectorAll('[data-key-eye] svg.key-eye-icon').length,
              keyEyePressed: document.querySelector('[data-key-eye]').getAttribute('aria-pressed'),
              footerButtonSizes: [...document.querySelectorAll('.settings-modal footer button')].map(button => {
                const rect = button.getBoundingClientRect();
                return {width: rect.width, height: rect.height};
              }),
            };
          })()
        """)
        assert modal["bodyLocked"], modal
        assert modal["viewportFit"], modal
        assert modal["fieldOverflow"] == 0, modal
        assert modal["keyPoolInputs"] == 5, modal
        assert modal["keyEyes"] == 5, modal
        assert modal["keyEyeSvgs"] == 5, modal
        assert modal["keyEyePressed"] == "false", modal
        assert len(modal["footerButtonSizes"]) == 2, modal
        assert abs(modal["footerButtonSizes"][0]["width"] - modal["footerButtonSizes"][1]["width"]) <= 1, modal
        assert abs(modal["footerButtonSizes"][0]["height"] - modal["footerButtonSizes"][1]["height"]) <= 1, modal
        assert modal["footerButtonSizes"][0]["height"] >= 48, modal
        cdp.evaluate("document.querySelector('[data-key-eye]').click()")
        assert cdp.evaluate("document.querySelector('[data-key-eye]').getAttribute('aria-pressed')") == "true"
        assert cdp.evaluate("document.querySelector('[data-key-eye] svg.key-eye-icon') !== null")
        assert cdp.evaluate("document.querySelector('[data-key-eye]').getAttribute('aria-label')") == "隐藏 Key 短前缀"
        cdp.screenshot(Path(args.screenshot))
        cdp.evaluate("document.querySelector('[data-close=" + json.dumps("settingsModal") + "]').click()")
        wait_for(lambda: cdp.evaluate("document.querySelector('#settingsModal').classList.contains('hidden')"), message="settings close")

        cdp.evaluate("""
          document.querySelector('#nodeText').value = `socks://demo-us.invalid:1080#Demo-US-Node-01
socks://demo-jp.invalid:1080#Demo-JP-Node-02`;
          document.querySelector('#importButton').click();
        """)
        wait_for(lambda: cdp.evaluate("!document.querySelector('#importSummary').classList.contains('hidden')"), message="UI node import")
        assert cdp.evaluate("document.querySelector('#metricImported').textContent") == "2"
        assert cdp.evaluate("document.querySelector('#startButton').disabled") is True
        assert "确认节点授权" in cdp.evaluate("document.querySelector('#startHint').textContent")
        assert cdp.evaluate("document.querySelectorAll('#resultBody tr').length") == 2
        assert cdp.evaluate("document.querySelector('#resultBody .status-pending').textContent") == "待检测"
        assert "Demo-US-Node-01" in cdp.evaluate("document.querySelector('#resultBody').textContent")
        cdp.evaluate("document.querySelector('[data-node-select]').click()")
        assert "已选择 1 个节点" in cdp.evaluate("document.querySelector('#selectionCount').textContent")
        assert "确认节点授权" in cdp.evaluate("document.querySelector('#startHint').textContent")

        cdp.call("Page.reload", {"ignoreCache": True})
        wait_for(lambda: cdp.evaluate("document.readyState === 'complete'"), message="preview page reload")
        wait_for(lambda: cdp.evaluate("document.querySelectorAll('#resultBody tr').length === 2"), message="import preview restore")
        assert cdp.evaluate("document.querySelector('#resultBody .status-pending').textContent") == "待检测"
        cdp.evaluate("document.querySelector('[data-node-select]').click()")
        assert "已选择 1 个节点" in cdp.evaluate("document.querySelector('#selectionCount').textContent")
        preview_screenshot = Path(args.screenshot).with_name(Path(args.screenshot).stem + "-preview" + Path(args.screenshot).suffix)
        cdp.screenshot(preview_screenshot)
        if args.write_demo_assets:
            cdp.screenshot(ROOT / "docs" / "assets" / "dashboard-dark-demo.png")
        cdp.evaluate("document.querySelector('.control-rail').scrollTop = document.querySelector('.control-rail').scrollHeight")
        compliance_screenshot = Path(args.screenshot).with_name(Path(args.screenshot).stem + "-compliance" + Path(args.screenshot).suffix)
        cdp.screenshot(compliance_screenshot)
        if args.write_demo_assets:
            cdp.screenshot(ROOT / "docs" / "assets" / "authorization-gate-demo.png")
        cdp.evaluate("document.querySelector('.control-rail').scrollTop = 0")

        previous_theme = cdp.evaluate("document.documentElement.dataset.theme")
        cdp.evaluate("document.querySelector('#themeButton').click()")
        assert cdp.evaluate("document.documentElement.dataset.theme") != previous_theme
        cdp.evaluate("""
          document.querySelector('#settingsButton').click();
          const theme = document.querySelector('#themeSelect');
          theme.value = 'light'; theme.dispatchEvent(new Event('change', {bubbles:true}));
          const font = document.querySelector('#fontSizeSelect');
          font.value = 'xlarge'; font.dispatchEvent(new Event('change', {bubbles:true}));
        """)
        assert cdp.evaluate("document.documentElement.dataset.fontSize") == "xlarge"
        light_settings_screenshot = Path(args.screenshot).with_name(Path(args.screenshot).stem + "-settings-light" + Path(args.screenshot).suffix)
        cdp.screenshot(light_settings_screenshot)
        light_screenshot = Path(args.screenshot).with_name(Path(args.screenshot).stem + "-light" + Path(args.screenshot).suffix)
        cdp.evaluate("document.querySelector('[data-close=" + json.dumps("settingsModal") + "]').click()")
        cdp.screenshot(light_screenshot)
        if args.write_demo_assets:
            cdp.screenshot(ROOT / "docs" / "assets" / "dashboard-light-demo.png")
        cdp.evaluate("document.querySelector('#authorizationConfirm').click()")
        assert cdp.evaluate("document.querySelector('#startButton').disabled") is False
        assert "仅检测已选 1 个节点" in cdp.evaluate("document.querySelector('#startHint').textContent")
        cdp.evaluate("document.querySelector('#startButton').click()")
        generated_task_id = wait_for(
            lambda: cdp.evaluate("sessionStorage.getItem('proxyAudit.currentTask')"),
            message="acceptance task id",
        )
        wait_for(
            lambda: cdp.evaluate("document.querySelector('#taskTitle').textContent.includes('检测完成')"),
            timeout=20,
            message="UI task completion",
        )
        assert cdp.evaluate("document.querySelectorAll('#resultBody tr').length") == 1
        assert cdp.evaluate("document.querySelector('#metricImported').textContent") == "1"
        assert cdp.evaluate("document.querySelector('#exportJson').disabled") is False
        cdp.call("Page.reload", {"ignoreCache": True})
        wait_for(lambda: cdp.evaluate("document.readyState === 'complete'"), message="result page reload")
        wait_for(lambda: cdp.evaluate("document.querySelector('#taskTitle').textContent.includes('检测完成')"), message="task result restore")
        assert cdp.evaluate("document.querySelectorAll('#resultBody tr').length") == 1
        assert cdp.evaluate("document.querySelector('#metricImported').textContent") == "1"
        assert cdp.evaluate("document.documentElement.dataset.theme") == "light"
        assert cdp.evaluate("document.documentElement.dataset.fontSize") == "xlarge"
        cdp.evaluate("document.querySelector(`[data-rename-task='${sessionStorage.getItem('proxyAudit.currentTask')}']`).click()")
        wait_for(lambda: cdp.evaluate("!document.querySelector('#renameModal').classList.contains('hidden')"), message="rename modal")
        cdp.evaluate("document.querySelector('#renameTaskInput').value = 'Browser renamed history'; document.querySelector('#saveTaskName').click()")
        wait_for(lambda: cdp.evaluate("document.querySelector('#historyList').textContent.includes('Browser renamed history')"), message="renamed history")
        assert "Browser renamed history" in cdp.evaluate("document.querySelector('#taskTitle').textContent")
        cdp.evaluate("""
          const status = document.querySelector('#statusFilter');
          status.value = 'skipped'; status.dispatchEvent(new Event('input', {bubbles:true}));
        """)
        assert cdp.evaluate("document.querySelectorAll('#resultBody tr').length") == 1
        cdp.evaluate("""
          const search = document.querySelector('#resultSearch');
          search.value = 'definitely-no-match'; search.dispatchEvent(new Event('input', {bubbles:true}));
        """)
        assert cdp.evaluate("document.querySelectorAll('#resultBody tr').length") == 0
        assert cdp.evaluate("!document.querySelector('#emptyState').classList.contains('hidden')")
        assert not cdp.exceptions, cdp.exceptions

        cdp.call("Page.navigate", {"url": f"http://127.0.0.1:{app_port}/legal"})
        wait_for(lambda: cdp.evaluate("document.readyState === 'complete'"), message="legal page load")
        assert cdp.evaluate("document.title") == "Proxy Audit · 使用与隐私说明"
        assert cdp.evaluate("document.querySelector('h1').textContent") == "使用、隐私与安全边界"
        assert cdp.evaluate("document.querySelectorAll('.legal-section').length") == 4
        assert cdp.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        legal_screenshot = Path(args.screenshot).with_name(Path(args.screenshot).stem + "-legal" + Path(args.screenshot).suffix)
        cdp.screenshot(legal_screenshot)
        if args.write_demo_assets:
            cdp.screenshot(ROOT / "docs" / "assets" / "legal-privacy-page.png")
        assert not cdp.exceptions, cdp.exceptions

        summary = {
            "status": "passed",
            "viewport": f"{args.width}x{args.height}",
            "geometry": geometry,
            "settingsModal": modal,
            "uiImport": "passed",
            "importPreviewRestore": "passed",
            "uiTask": "passed",
            "taskResultRestore": "passed",
            "partialSelection": "passed",
            "authorizationGate": "passed",
            "historicalMetricContext": "passed",
            "historyRename": "passed",
            "themeAndFontPersistence": "passed",
            "resultFiltering": "passed",
            "legalPage": "passed",
            "javascriptExceptions": 0,
            "screenshot": str(Path(args.screenshot)),
            "previewScreenshot": str(preview_screenshot),
            "complianceScreenshot": str(compliance_screenshot),
            "lightScreenshot": str(light_screenshot),
            "lightSettingsScreenshot": str(light_settings_screenshot),
            "legalScreenshot": str(legal_screenshot),
        }
        print(json.dumps(summary, ensure_ascii=False))
    finally:
        if cdp:
            try:
                cdp.close()
            except Exception:
                pass
        for proc in (chrome_proc, app_proc):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        cleanup_acceptance_run(generated_task_id)


if __name__ == "__main__":
    main()
