"""Run privacy-safe, real-network acceptance checks against a local v2rayN DB.

The script never prints node names, servers, credentials, subscription URLs, or
exit IPs.  It prints one JSON object per protocol/kernel pair so a failed or
expired node is not confused with a parser/core implementation failure.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from collections import defaultdict
from pathlib import Path
from threading import Event


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from lib_kernels import describe_kernel_support, kernel_catalog  # noqa: E402
from lib_runner import run_node  # noqa: E402
from lib_v2rayn import load_from_v2ray_db  # noqa: E402


DEFAULT_PAIRS = (
    ("sing-box", "vless"),
    ("sing-box", "vmess"),
    ("sing-box", "trojan"),
    ("sing-box", "ss"),
    ("sing-box", "hysteria2"),
    ("sing-box", "tuic"),
    ("sing-box", "anytls"),
    ("xray", "vless"),
    ("xray", "vmess"),
    ("xray", "trojan"),
    ("xray", "ss"),
)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def spread(items, limit: int):
    """Pick candidates across the DB instead of one possibly stale subscription."""
    if len(items) <= limit:
        return list(items)
    if limit == 1:
        return [items[len(items) // 2]]
    positions = [round(index * (len(items) - 1) / (limit - 1)) for index in range(limit)]
    return [items[position] for position in positions]


def error_category(item) -> str:
    error = str(item.get("error") or "")
    log_tail = str(item.get("log_tail") or "")
    combined = (error + "\n" + log_tail).lower()
    if "did not become ready" in combined or "failed to start" in combined:
        return "core_startup_or_config"
    if any(token in combined for token in ("timeout", "proxyerror", "connection", "eof", "tls handshake")):
        return "node_or_upstream_unreachable"
    if any(token in combined for token in ("invalid", "fatal", "decode", "parse")):
        return "core_rejected_config"
    return "runtime_error"


def parse_pairs(values):
    if not values:
        return DEFAULT_PAIRS
    pairs = []
    for value in values:
        kernel, separator, protocol = value.partition(":")
        if not separator or kernel not in {"sing-box", "xray"} or not protocol:
            raise argparse.ArgumentTypeError(f"Invalid pair: {value}")
        pairs.append((kernel, protocol.lower()))
    return tuple(pairs)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, help="Path to guiNDB.db")
    parser.add_argument("--pair", action="append", help="kernel:protocol; repeatable")
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--services", nargs="*", default=[])
    parser.add_argument("--providers", nargs="+", default=["ip_api"])
    args = parser.parse_args()

    pairs = parse_pairs(args.pair)
    nodes = load_from_v2ray_db(args.db)
    grouped = defaultdict(list)
    for node in nodes:
        grouped[str(node.get("protocol") or "unknown").lower()].append(node)

    catalog = {item["id"]: item for item in kernel_catalog()}
    print(json.dumps({
        "event": "environment",
        "database_nodes": len(nodes),
        "kernels": {
            key: {"available": value["available"], "version": value["version"]}
            for key, value in catalog.items()
        },
        "privacy": "node identity, server, credentials, subscription URL and exit IP omitted",
    }, ensure_ascii=False), flush=True)

    total_success = 0
    for pair_index, (kernel, protocol) in enumerate(pairs, start=1):
        compatible = [node for node in grouped.get(protocol, []) if describe_kernel_support(kernel, node)[0]]
        candidates = spread(compatible, max(1, args.max_attempts))
        attempts = []
        success_summary = None
        for attempt_index, node in enumerate(candidates, start=1):
            item = run_node(
                node=node,
                index=pair_index * 100 + attempt_index,
                run_id=f"accept_{int(time.time())}",
                kernel=kernel,
                socks_port=free_port(),
                timeout=max(3, args.timeout),
                providers=args.providers,
                service_targets=args.services,
                quality_samples=2,
                cancel_event=Event(),
            )
            if item.get("success"):
                result = item.get("result") or {}
                unified = result.get("unified") or {}
                ip_api = result.get("ip_api") or {}
                quality = result.get("quality") or {}
                services = result.get("services") or {}
                success_summary = {
                    "core_startup_ms": item.get("core_startup_ms"),
                    "country_code": ip_api.get("countryCode"),
                    "network_type": unified.get("ip_type_final"),
                    "risk_level": unified.get("risk_level_final"),
                    "quality_success_rate": quality.get("success_rate"),
                    "latency_median_ms": quality.get("latency_median_ms"),
                    "provider_data": {
                        provider: bool(result.get(provider))
                        for provider in args.providers
                    },
                    "provider_error_keys": sorted((result.get("intel_errors") or {}).keys()),
                    "services": {
                        key: {"reachable": value.get("reachable"), "status": value.get("status")}
                        for key, value in services.items()
                    },
                }
                attempts.append("success")
                total_success += 1
                break
            attempts.append(error_category(item))

        print(json.dumps({
            "event": "pair_result",
            "kernel": kernel,
            "protocol": protocol,
            "compatible_nodes": len(compatible),
            "attempted": len(attempts),
            "attempt_outcomes": attempts,
            "live_success": success_summary is not None,
            "success": success_summary,
        }, ensure_ascii=False), flush=True)

    print(json.dumps({
        "event": "summary",
        "pairs": len(pairs),
        "pairs_with_live_success": total_success,
        "pairs_without_live_success": len(pairs) - total_success,
    }, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
