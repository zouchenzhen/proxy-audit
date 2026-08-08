import time
from pathlib import Path
from threading import Event
from typing import Any, Dict

from lib_ipintel import probe_ip_via_socks
from lib_kernels import describe_kernel_support, start_kernel, stop_kernel
from lib_paths import CONFIG_DIR, LOG_DIR
from lib_singbox import wait_port


def tail_text(path: Path, chars: int = 2400) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[-chars:]
    except Exception:
        return ""


def friendly_run_error(error: Exception, log_tail: str = "") -> str:
    """Return a stable, user-facing category without leaking object addresses."""
    detail = f"{type(error).__name__}: {error}"
    combined = f"{detail}\n{log_tail}".lower()
    if "unsupported usage for utls" in combined:
        return "内核配置不兼容：当前协议不能使用 uTLS 指纹"
    if "did not become ready" in combined:
        return "检测内核未能启动本地 SOCKS 监听"
    if "general socks server failure" in combined:
        return "代理内核未能建立出站连接（节点、协议参数或上游网络异常）"
    if any(token in combined for token in ("timed out", "timeout", "deadline exceeded")):
        return "节点出站连接超时"
    if any(token in combined for token in ("connection refused", "actively refused")):
        return "节点服务器拒绝连接"
    if any(token in combined for token in ("certificate", "tls handshake", "handshake failed")):
        return "节点 TLS 握手失败"
    return f"{type(error).__name__}：检测失败（详情见本机内核日志）"


def run_node(
    node: Dict[str, Any],
    index: int,
    run_id: str,
    kernel: str,
    socks_port: int,
    timeout: int,
    providers,
    service_targets,
    quality_samples: int,
    cancel_event: Event,
) -> Dict[str, Any]:
    supported, reason = describe_kernel_support(kernel, node)
    safe_name = f"{run_id}_{index:04d}_{kernel.replace('-', '_')}"
    config_path = CONFIG_DIR / f"{safe_name}.json"
    log_path = LOG_DIR / f"{safe_name}.log"
    item = {
        "index": index,
        "kernel": kernel,
        "supported": supported,
        "success": False,
        "cancelled": False,
        "skip_reason": "" if supported else reason,
        "error": None,
        "node": node,
        "socks_port": socks_port,
        "config_path": str(config_path),
        "log_path": str(log_path),
        "core_startup_ms": None,
        "result": None,
        "log_tail": "",
    }
    if not supported:
        return item
    if cancel_event.is_set():
        item.update({"cancelled": True, "skip_reason": "Task cancelled before node start"})
        return item

    proc = None
    try:
        started = time.perf_counter()
        proc = start_kernel(kernel, node, socks_port, config_path, log_path)
        if not wait_port(socks_port, deadline_sec=max(10, timeout + 3)):
            raise RuntimeError(f"{kernel} local SOCKS listener did not become ready")
        item["core_startup_ms"] = round((time.perf_counter() - started) * 1000, 1)
        if cancel_event.is_set():
            item.update({"cancelled": True, "skip_reason": "Task cancelled"})
            return item
        item["result"] = probe_ip_via_socks(
            socks_port,
            timeout=timeout,
            providers=providers,
            service_targets=service_targets,
            quality_samples=quality_samples,
        )
        item["success"] = True
        return item
    except Exception as exc:
        item["log_tail"] = tail_text(log_path)
        item["error"] = friendly_run_error(exc, item["log_tail"])
        return item
    finally:
        if proc is not None:
            stop_kernel(proc)
        try:
            config_path.unlink(missing_ok=True)
            item["config_path"] = None
        except OSError:
            pass
        if not item["log_tail"] and not item["success"]:
            item["log_tail"] = tail_text(log_path)
