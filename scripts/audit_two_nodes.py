import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

import requests

from lib_paths import ROOT, CONFIG_DIR, LOG_DIR, RESULT_DIR
from lib_singbox import resolve_singbox_binary

BIN = resolve_singbox_binary()

NODES = [
    line.strip()
    for line in os.environ.get("PROXY_AUDIT_NODES", "").splitlines()
    if line.strip()
]


def ensure_dirs():
    for p in (CONFIG_DIR, LOG_DIR, RESULT_DIR):
        p.mkdir(parents=True, exist_ok=True)


def parse_vless(url: str) -> dict:
    u = urlparse(url)
    q = parse_qs(u.query)
    return {
        "raw": url,
        "name": unquote(u.fragment) if u.fragment else f"{u.hostname}:{u.port}",
        "uuid": u.username,
        "server": u.hostname,
        "server_port": u.port or 443,
        "network": q.get("type", ["tcp"])[0],
        "security": q.get("security", [""])[0],
        "sni": q.get("sni", [u.hostname])[0],
        "host": q.get("host", [u.hostname])[0],
        "path": unquote(q.get("path", ["/"])[0]),
        "fp": q.get("fp", [""])[0],
        "insecure": q.get("insecure", q.get("allowInsecure", ["0"]))[0] in ("1", "true", "True"),
    }


def make_config(node: dict, socks_port: int) -> dict:
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": node["server"],
        "server_port": node["server_port"],
        "uuid": node["uuid"],
        "tls": {
            "enabled": node["security"] == "tls",
            "server_name": node["sni"],
            "insecure": node["insecure"],
            "utls": {
                "enabled": bool(node["fp"]),
                "fingerprint": node["fp"] or "chrome",
            },
        },
    }
    if node["network"] == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": node["path"],
            "headers": {
                "Host": node["host"]
            }
        }
    return {
        "log": {
            "level": "info",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            }
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "final": "proxy"
        }
    }


def is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def wait_port(port: int, deadline_sec: int = 15):
    start = time.time()
    while time.time() - start < deadline_sec:
        if is_port_open("127.0.0.1", port):
            return True
        time.sleep(0.4)
    return False


def probe_ip(socks_port: int, timeout: int = 12):
    proxies = {
        "http": f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}",
    }
    session = requests.Session()
    session.proxies.update(proxies)
    session.trust_env = False

    r1 = session.get("https://api.ipify.org?format=json", timeout=timeout)
    r1.raise_for_status()
    ip = r1.json().get("ip")

    r2 = session.get(
        f"http://ip-api.com/json/{ip}?fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting",
        timeout=timeout,
    )
    r2.raise_for_status()
    return {"ipify": r1.json(), "ip_api": r2.json()}


def run_one(node_url: str, index: int, socks_port: int) -> dict:
    node = parse_vless(node_url)
    safe_name = f"node_{index:02d}"
    cfg_path = CONFIG_DIR / f"{safe_name}.json"
    log_path = LOG_DIR / f"{safe_name}.log"
    config = make_config(node, socks_port)
    cfg_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")

    with log_path.open("w", encoding="utf-8") as logf:
        proc = subprocess.Popen(
            [str(BIN), "run", "-c", str(cfg_path)],
            stdout=logf,
            stderr=subprocess.STDOUT,
            cwd=str(ROOT),
        )
        try:
            if not wait_port(socks_port, 18):
                raise RuntimeError("sing-box local socks port did not become ready in time")
            data = probe_ip(socks_port)
            return {
                "success": True,
                "node": node,
                "socks_port": socks_port,
                "config_path": str(cfg_path),
                "log_path": str(log_path),
                "result": data,
            }
        except Exception as e:
            try:
                log_tail = log_path.read_text(encoding="utf-8", errors="ignore")[-4000:]
            except Exception:
                log_tail = ""
            return {
                "success": False,
                "node": node,
                "socks_port": socks_port,
                "config_path": str(cfg_path),
                "log_path": str(log_path),
                "error": repr(e),
                "log_tail": log_tail,
            }
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()


def main():
    ensure_dirs()
    if not BIN.exists():
        raise FileNotFoundError(f"sing-box not found: {BIN}")
    if not NODES:
        raise RuntimeError(
            "No nodes configured. Set PROXY_AUDIT_NODES to one or more "
            "newline-separated VLESS share links."
        )
    results = []
    base_port = 21080
    for idx, node_url in enumerate(NODES, start=1):
        results.append(run_one(node_url, idx, base_port + idx - 1))
    out = RESULT_DIR / f"run_{int(time.time())}.json"
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(str(out))
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
