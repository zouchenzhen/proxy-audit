import subprocess
from pathlib import Path
from typing import Any, Dict

from lib_singbox import (
    build_singbox_config,
    resolve_singbox_binary,
    start_singbox,
    stop_singbox,
    write_config_file,
)
from lib_v2rayn import describe_support
from lib_xray import (
    build_xray_config,
    describe_xray_support,
    resolve_xray_binary,
    start_xray,
    write_xray_config,
)


KERNELS = {"sing-box", "xray"}


def _version(binary: Path, kernel: str) -> str:
    if not binary.exists():
        return ""
    try:
        args = [str(binary), "version"]
        completed = subprocess.run(args, capture_output=True, text=True, timeout=4, encoding="utf-8", errors="replace")
        first = (completed.stdout or completed.stderr or "").strip().splitlines()
        return first[0] if first else ""
    except Exception:
        return ""


def kernel_catalog():
    singbox = resolve_singbox_binary()
    xray = resolve_xray_binary()
    return [
        {
            "id": "sing-box",
            "name": "sing-box",
            "available": singbox.exists(),
            "path": str(singbox),
            "version": _version(singbox, "sing-box"),
            "protocols": ["vless", "vmess", "trojan", "ss", "anytls", "hysteria2", "tuic"],
        },
        {
            "id": "xray",
            "name": "Xray",
            "available": xray.exists(),
            "path": str(xray),
            "version": _version(xray, "xray"),
            "protocols": ["vless", "vmess", "trojan", "ss"],
        },
    ]


def describe_kernel_support(kernel: str, node: Dict[str, Any]):
    if kernel == "sing-box":
        return describe_support(node)
    if kernel == "xray":
        return describe_xray_support(node)
    return False, f"Unknown kernel: {kernel}"


def start_kernel(kernel: str, node: Dict[str, Any], socks_port: int, config_path: Path, log_path: Path):
    if kernel == "sing-box":
        write_config_file(build_singbox_config(node, socks_port), config_path)
        return start_singbox(config_path, log_path)
    if kernel == "xray":
        write_xray_config(build_xray_config(node, socks_port), config_path)
        return start_xray(config_path, log_path)
    raise ValueError(f"Unknown kernel: {kernel}")


def stop_kernel(proc) -> None:
    stop_singbox(proc)
