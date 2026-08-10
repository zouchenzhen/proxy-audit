"""Isolated browser acceptance for the same-origin ephemeral cloud UI.

Uses only synthetic public-IP nodes and mocks the core runner. It never touches
the user's normal browser profile or persisted local task history.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cloud_app
import lib_tasks
from ui_browser_acceptance import CDP, find_chrome, free_port, wait_for


def synthetic_result(node, index, _run_id, kernel, _port, *_args, **_kwargs):
    time.sleep(0.03)
    return {
        "index": index,
        "kernel": kernel,
        "supported": True,
        "success": True,
        "cancelled": False,
        "skip_reason": "",
        "error": None,
        "node": node,
        "core_startup_ms": 12.5,
        "result": {
            "ipify": {"ip": f"203.0.113.{index}"},
            "ipify_latency_ms": 22.0,
            "ip_api": {"country": "Example", "city": "Test", "as": "AS64500"},
            "unified": {
                "ip_type_final": "datacenter",
                "risk_score_final": 18,
                "risk_level_final": "low",
                "native_ip_judgement": "unknown",
                "reasoning_brief": "synthetic browser acceptance",
            },
            "quality": {"latency_median_ms": 88.0, "jitter_ms": 2.0},
            "services": {},
        },
    }


def main() -> None:
    port = free_port()
    app = cloud_app.create_app(testing=True, session_store=cloud_app.CloudSessionStore())
    server = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False),
        daemon=True,
    )
    chrome = find_chrome()
    profile = Path(tempfile.mkdtemp(prefix="proxy-audit-cloud-chrome-"))
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    cdp = None
    with patch.object(cloud_app, "pin_public_node", side_effect=lambda node: {
        **node,
        "_display_server": node["server"],
        "server": "93.184.216.34",
    }), patch.object(lib_tasks, "run_node", side_effect=synthetic_result):
        server.start()
        wait_for(lambda: urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1).status == 200, message="cloud test server")
        chrome_proc = subprocess.Popen([
            str(chrome), "--headless=new", "--disable-gpu", "--no-first-run",
            "--no-default-browser-check", "--remote-allow-origins=*", "--remote-debugging-port=0",
            f"--user-data-dir={profile}", "--window-size=1536,900", "about:blank",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creationflags)
        try:
            port_file = profile / "DevToolsActivePort"
            wait_for(port_file.exists, message="Chrome DevTools port")
            debug_port = int(port_file.read_text(encoding="utf-8").splitlines()[0])
            targets = lambda: json.loads(urllib.request.urlopen(f"http://127.0.0.1:{debug_port}/json/list", timeout=2).read())
            target = wait_for(lambda: next((item for item in targets() if item.get("type") == "page"), None), message="Chrome target")
            cdp = CDP(target["webSocketDebuggerUrl"])
            for domain in ("Page", "Runtime", "Network", "Log"):
                cdp.call(f"{domain}.enable")
            cdp.call("Page.navigate", {"url": f"http://127.0.0.1:{port}/?cloud=1"})
            wait_for(lambda: cdp.evaluate("document.readyState === 'complete'"), message="page load")
            wait_for(lambda: cdp.evaluate("!document.querySelector('#onlineModeModal').classList.contains('hidden')"), message="privacy modal")
            modal = cdp.evaluate("document.querySelector('.online-mode-modal').textContent")
            assert "上传到临时云端后端" in modal and "最长 12 秒" in modal
            cdp.evaluate("document.querySelector('#startCloudSession').click()")
            wait_for(lambda: cdp.evaluate("document.querySelector('#healthText').textContent.includes('云端临时会话已连接')"), message="session ready")
            assert cdp.evaluate("document.querySelector('#settingsTitle').textContent") == "临时会话设置"
            cdp.evaluate("""
              document.querySelector('#nodeText').value = [
                ['vless', '://00000000-0000-0000-0000-000000000001@one.example:443?security=tls#Cloud-One'].join(''),
                ['trojan', '://synthetic-password@two.example:443?security=tls#Cloud-Two'].join('')
              ].join('\\n');
              document.querySelector('#importButton').click();
            """)
            wait_for(lambda: cdp.evaluate("document.querySelector('#metricImported').textContent === '2'"), message="import preview")
            assert "Cloud-One" in cdp.evaluate("document.querySelector('#resultBody').textContent")
            cdp.evaluate("""
              const boxes = document.querySelectorAll('[data-node-select]');
              boxes[0].click();
              document.querySelector('#authorizationConfirm').click();
              document.querySelector('#startButton').click();
            """)
            wait_for(lambda: cdp.evaluate("document.querySelector('#progressText').textContent === '100%'"), timeout=10, message="cloud task")
            assert cdp.evaluate("document.querySelector('#metricImported').textContent") == "1"
            assert cdp.evaluate("document.querySelector('#metricSuccess').textContent") == "1"
            assert cdp.evaluate("document.querySelector('#resultBody').textContent.includes('203.0.113.1')")
            cdp.evaluate("document.querySelector('#deleteCloudSession').click()")
            wait_for(lambda: cdp.evaluate("document.querySelector('#healthText').textContent === '云端数据已删除'"), message="manual delete")
            assert cdp.evaluate("sessionStorage.getItem('proxyAudit.cloudSession') === null")
            assert not cdp.exceptions, cdp.exceptions
            print(json.dumps({"status": "passed", "session": "isolated", "partialSelection": 1, "manualDelete": True, "javascriptExceptions": 0}))
        finally:
            if cdp:
                cdp.close()
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
