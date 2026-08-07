import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from lib_paths import BIN_DIR, ROOT
from lib_secrets import load_settings


DEFAULT_BIN = BIN_DIR / "xray.exe"


def resolve_xray_binary() -> Path:
    configured = load_settings().get("xray_path")
    candidates = [
        Path(configured) if configured else None,
        DEFAULT_BIN,
        Path(shutil.which("xray")) if shutil.which("xray") else None,
        Path(r"E:\application\v2rayN-windows-64-SelfContained\bin\xray\xray.exe"),
    ]
    return next((path for path in candidates if path and path.exists()), DEFAULT_BIN)


def describe_xray_support(node: Dict[str, Any]):
    proto = (node.get("protocol") or "").lower()
    network = (node.get("network") or "tcp").lower()
    tls_mode = (node.get("tls_mode") or "").lower()
    if proto not in {"vless", "vmess", "trojan", "ss"}:
        return False, f"Xray does not support this project mapping for: {proto}"
    if proto != "ss" and network not in {"tcp", "ws", ""}:
        return False, f"Xray {proto} transport not implemented: {network}"
    if proto != "ss" and tls_mode not in {"", "tls", "reality"}:
        return False, f"Xray {proto} security mode not implemented: {tls_mode}"
    if tls_mode == "reality" and not node.get("public_key"):
        return False, "Reality node missing public key"
    if not node.get("server") or not node.get("server_port"):
        return False, "Node missing server/port"
    return True, ""


def _stream_settings(node: Dict[str, Any]) -> Dict[str, Any]:
    network = (node.get("network") or "tcp").lower()
    tls_mode = (node.get("tls_mode") or "").lower()
    stream: Dict[str, Any] = {"network": network or "tcp"}
    if network == "ws":
        stream["wsSettings"] = {
            "path": node.get("path") or "/",
            "headers": {"Host": node.get("host") or node.get("server")},
        }
    if tls_mode == "tls":
        stream["security"] = "tls"
        tls = {
            "serverName": node.get("sni") or node.get("server"),
            "allowInsecure": bool(node.get("insecure")),
        }
        if node.get("fp"):
            tls["fingerprint"] = node.get("fp")
        if node.get("alpn"):
            tls["alpn"] = [x.strip() for x in str(node.get("alpn")).split(",") if x.strip()]
        stream["tlsSettings"] = tls
    elif tls_mode == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": node.get("sni") or node.get("server"),
            "fingerprint": node.get("fp") or "chrome",
            "publicKey": node.get("public_key"),
            "shortId": node.get("short_id") or "",
        }
    return stream


def build_xray_config(node: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    supported, reason = describe_xray_support(node)
    if not supported:
        raise ValueError(reason)
    proto = (node.get("protocol") or "").lower()
    address = node.get("server")
    port = int(node.get("server_port"))

    if proto in {"vless", "vmess"}:
        user: Dict[str, Any] = {"id": node.get("uuid")}
        if proto == "vless":
            user["encryption"] = node.get("security") or "none"
            if node.get("flow"):
                user["flow"] = node.get("flow")
        else:
            user["alterId"] = int(node.get("alter_id") or 0)
            user["security"] = node.get("security") or "auto"
        outbound = {
            "protocol": proto,
            "tag": "proxy",
            "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]},
            "streamSettings": _stream_settings(node),
        }
    elif proto == "trojan":
        outbound = {
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {"servers": [{"address": address, "port": port, "password": node.get("password") or node.get("uuid")}]},
            "streamSettings": _stream_settings(node),
        }
    else:
        outbound = {
            "protocol": "shadowsocks",
            "tag": "proxy",
            "settings": {"servers": [{
                "address": address,
                "port": port,
                "method": node.get("security"),
                "password": node.get("password"),
            }]},
        }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "tag": "socks-in",
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def start_xray(config_path: Path, log_path: Path, binary_path: Optional[Path] = None) -> subprocess.Popen:
    binary = Path(binary_path) if binary_path else resolve_xray_binary()
    if not binary.exists():
        raise FileNotFoundError(f"Xray not found: {binary}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logf = log_path.open("w", encoding="utf-8")
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    proc = subprocess.Popen(
        [str(binary), "run", "-c", str(config_path)],
        stdout=logf,
        stderr=subprocess.STDOUT,
        cwd=str(ROOT),
        **kwargs,
    )
    proc._proxy_audit_logf = logf
    return proc


def write_xray_config(config: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
