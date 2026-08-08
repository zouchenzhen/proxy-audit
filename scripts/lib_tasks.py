import csv
import io
import json
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from lib_ipintel import DEFAULT_PROVIDERS, SERVICE_TARGETS
from lib_paths import RESULT_CSV, RESULT_RAW, RESULT_REPORT, ensure_project_dirs
from lib_report import build_summary_rows, write_csv, write_markdown_report
from lib_runner import run_node
from lib_secrets import load_settings
from lib_v2rayn import filter_nodes


WEB_RUN_PATTERN = re.compile(r"^run_(\d{8}_\d{6}_[0-9a-f]{6})\.json$")


def safe_node(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "remark": node.get("remark"),
        "protocol": node.get("protocol"),
        "server": node.get("server"),
        "server_port": node.get("server_port"),
        "network": node.get("network"),
        "tls_mode": node.get("tls_mode"),
        "sni": node.get("sni"),
        "host": node.get("host"),
        "path": node.get("path"),
        "source_type": node.get("source_type"),
        "source_name": node.get("source_name"),
        "subscription_name": node.get("subscription_name"),
        "parse_error": node.get("parse_error"),
    }


def protocol_counts(nodes: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for node in nodes:
        proto = (node.get("protocol") or "unknown").lower()
        counts[proto] = counts.get(proto, 0) + 1
    return counts


class TaskManager:
    def __init__(self, history_limit: Optional[int] = None):
        ensure_project_dirs()
        self.imports: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self._cancel: Dict[str, threading.Event] = {}
        self._lock = threading.RLock()
        configured_limit = history_limit if history_limit is not None else load_settings().get("history_limit", 10)
        self.history_limit = max(1, min(int(configured_limit or 10), 100))
        self.reload_history(self.history_limit)

    def add_import(self, nodes: List[Dict[str, Any]], source_label: str) -> Dict[str, Any]:
        import_id = uuid.uuid4().hex[:12]
        record = {
            "id": import_id,
            "source_label": source_label,
            "created_at": time.time(),
            "nodes": nodes,
        }
        with self._lock:
            self.imports[import_id] = record
            while len(self.imports) > 20:
                self.imports.pop(next(iter(self.imports)))
        return self.public_import(record)

    def public_import(self, record: Dict[str, Any], include_preview: bool = True) -> Dict[str, Any]:
        nodes = record["nodes"]
        output = {
            "id": record["id"],
            "source_label": record["source_label"],
            "created_at": record["created_at"],
            "total": len(nodes),
            "protocols": protocol_counts(nodes),
        }
        if include_preview:
            output["preview"] = [safe_node(node) for node in nodes[:500]]
            output["preview_count"] = len(output["preview"])
            output["preview_truncated"] = len(nodes) > len(output["preview"])
        return output

    def get_import(self, import_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.imports.get(import_id)

    def get_public_import(self, import_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self.imports.get(import_id)
            return self.public_import(record) if record else None

    def list_imports(self) -> List[Dict[str, Any]]:
        with self._lock:
            records = sorted(self.imports.values(), key=lambda item: item["created_at"], reverse=True)
            return [self.public_import(record, include_preview=False) for record in records]

    def start_task(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        imported = self.get_import(str(spec.get("import_id") or ""))
        if not imported:
            raise ValueError("Imported node set not found; please import nodes again")
        kernel = str(spec.get("kernel") or "sing-box")
        protocols = [str(x).lower() for x in spec.get("protocols") or []]
        selected = filter_nodes(
            imported["nodes"],
            filter_substring=str(spec.get("search") or ""),
            protocols=protocols,
            limit=int(spec.get("limit") or 0) or None,
        )
        if not selected:
            raise ValueError("No nodes match the current filters")
        task_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        providers = [p for p in (spec.get("providers") or DEFAULT_PROVIDERS) if p in set(DEFAULT_PROVIDERS) | {"abuseipdb"}]
        services = [s for s in (spec.get("service_targets") or []) if s in SERVICE_TARGETS]
        task = {
            "id": task_id,
            "status": "queued",
            "source_label": imported["source_label"],
            "kernel": kernel,
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "total": len(selected),
            "completed": 0,
            "success": 0,
            "failed": 0,
            "skipped": 0,
            "cancelled": 0,
            "progress": 0.0,
            "settings": {
                "timeout": max(4, min(int(spec.get("timeout") or 15), 90)),
                "concurrency": max(1, min(int(spec.get("concurrency") or 2), 8)),
                "providers": providers,
                "service_targets": services,
                "quality_samples": max(0, min(int(spec.get("quality_samples", 2)), 5)),
            },
            "events": [],
            "results": [],
            "rows": [],
            "paths": {},
            "nodes": selected,
        }
        cancel = threading.Event()
        with self._lock:
            self.tasks[task_id] = task
            self._cancel[task_id] = cancel
        threading.Thread(target=self._run_task, args=(task_id,), daemon=True, name=f"proxy-audit-{task_id}").start()
        return self.public_task(task)

    def _event(self, task: Dict[str, Any], level: str, message: str) -> None:
        task["events"].append({"time": time.time(), "level": level, "message": message})
        task["events"] = task["events"][-120:]

    def _run_task(self, task_id: str) -> None:
        with self._lock:
            task = self.tasks[task_id]
            cancel = self._cancel[task_id]
            task["status"] = "running"
            task["started_at"] = time.time()
            self._event(task, "info", f"开始检测 {task['total']} 个节点，内核 {task['kernel']}")
        settings = task["settings"]
        base_port = 23000 + (int(task_id[-6:], 16) % 25000)
        futures = {}
        with ThreadPoolExecutor(max_workers=settings["concurrency"], thread_name_prefix="node-probe") as pool:
            for index, node in enumerate(task["nodes"], start=1):
                future = pool.submit(
                    run_node,
                    node,
                    index,
                    task_id,
                    task["kernel"],
                    base_port + index - 1,
                    settings["timeout"],
                    settings["providers"],
                    settings["service_targets"],
                    settings["quality_samples"],
                    cancel,
                )
                futures[future] = (index, node)
            for future in as_completed(futures):
                index, node = futures[future]
                try:
                    item = future.result()
                except Exception as exc:
                    item = {
                        "index": index,
                        "kernel": task["kernel"],
                        "supported": True,
                        "success": False,
                        "cancelled": False,
                        "error": f"WorkerError: {exc}",
                        "skip_reason": "",
                        "node": node,
                        "result": None,
                    }
                with self._lock:
                    task["results"].append(item)
                    task["completed"] += 1
                    if item.get("success"):
                        task["success"] += 1
                        exit_ip = ((item.get("result") or {}).get("ipify") or {}).get("ip")
                        self._event(task, "success", f"{node.get('remark')}: {exit_ip}")
                    elif item.get("cancelled"):
                        task["cancelled"] += 1
                    elif not item.get("supported"):
                        task["skipped"] += 1
                        self._event(task, "warn", f"跳过 {node.get('remark')}: {item.get('skip_reason')}")
                    else:
                        task["failed"] += 1
                        self._event(task, "error", f"失败 {node.get('remark')}: {item.get('error')}")
                    task["progress"] = round(task["completed"] / task["total"] * 100, 1)
        with self._lock:
            task["results"].sort(key=lambda item: item.get("index") or 0)
            task["rows"] = build_summary_rows(task["results"])
            task["status"] = "cancelled" if cancel.is_set() else "completed"
            task["finished_at"] = time.time()
            self._event(task, "info", f"任务{task['status']}：成功 {task['success']}，失败 {task['failed']}，跳过 {task['skipped']}")
            self._persist(task)
            task.pop("nodes", None)

    def _persist(self, task: Dict[str, Any]) -> None:
        run_id = task["id"]
        raw_path = RESULT_RAW / f"run_{run_id}.json"
        csv_path = RESULT_CSV / f"run_{run_id}.csv"
        md_path = RESULT_REPORT / f"run_{run_id}.md"
        safe_results = []
        for item in task["results"]:
            safe_item = dict(item)
            safe_item["node"] = safe_node(item.get("node") or {})
            safe_item.pop("log_tail", None)
            safe_results.append(safe_item)
        payload = {
            "run_id": run_id,
            "source_label": task["source_label"],
            "kernel": task["kernel"],
            "settings": task["settings"],
            "status": task["status"],
            "created_at": task["created_at"],
            "started_at": task.get("started_at"),
            "finished_at": task["finished_at"],
            "events": task.get("events") or [],
            "results": safe_results,
        }
        raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_csv(csv_path, task["rows"])
        write_markdown_report(md_path, {"run_id": run_id, "source_label": task["source_label"]}, task["results"])
        task["paths"] = {"raw": str(raw_path), "csv": str(csv_path), "markdown": str(md_path)}
        # Keep only redacted node metadata in long-lived server memory.
        task["results"] = safe_results

    def cancel_task(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            if task_id not in self.tasks:
                raise KeyError(task_id)
            self._cancel[task_id].set()
            task = self.tasks[task_id]
            if task["status"] in {"queued", "running"}:
                task["status"] = "cancelling"
                self._event(task, "warn", "已请求取消；正在运行的单个节点会在当前超时后停止")
            return self.public_task(task)

    def public_task(self, task: Dict[str, Any], include_rows: bool = True) -> Dict[str, Any]:
        fields = (
            "id", "status", "source_label", "kernel", "created_at", "started_at", "finished_at",
            "total", "completed", "success", "failed", "skipped", "cancelled", "progress", "settings", "events", "paths",
        )
        output = {field: task.get(field) for field in fields}
        if include_rows:
            output["rows"] = task.get("rows") or build_summary_rows(task.get("results") or [])
        return output

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            task = self.tasks.get(task_id)
            return self.public_task(task) if task else None

    def list_tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            tasks = sorted(self.tasks.values(), key=lambda item: item.get("created_at") or 0, reverse=True)
            return [self.public_task(task, include_rows=False) for task in tasks[:self.history_limit]]

    def reload_history(self, history_limit: int) -> None:
        self.history_limit = max(1, min(int(history_limit or 10), 100))
        candidates = []
        for path in RESULT_RAW.glob("run_*.json"):
            match = WEB_RUN_PATTERN.match(path.name)
            if match:
                candidates.append((path.stat().st_mtime, match.group(1), path))
        for _mtime, run_id, path in sorted(candidates, reverse=True)[:self.history_limit]:
            if run_id in self.tasks:
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                results = payload.get("results") or []
                if not isinstance(results, list):
                    continue
                success = sum(1 for item in results if item.get("success"))
                skipped = sum(1 for item in results if item.get("supported") is False)
                cancelled = sum(1 for item in results if item.get("cancelled"))
                failed = len(results) - success - skipped - cancelled
                finished_at = payload.get("finished_at") or path.stat().st_mtime
                task = {
                    "id": run_id,
                    "status": payload.get("status") or "completed",
                    "source_label": payload.get("source_label") or "restored run",
                    "kernel": payload.get("kernel") or "unknown",
                    "created_at": payload.get("created_at") or finished_at,
                    "started_at": payload.get("started_at") or payload.get("created_at") or finished_at,
                    "finished_at": finished_at,
                    "total": len(results),
                    "completed": len(results),
                    "success": success,
                    "failed": failed,
                    "skipped": skipped,
                    "cancelled": cancelled,
                    "progress": 100.0,
                    "settings": payload.get("settings") or {},
                    "events": payload.get("events") or [{
                        "time": finished_at,
                        "level": "info",
                        "message": f"已从本机记录恢复：成功 {success}，失败 {failed}，跳过 {skipped}",
                    }],
                    "results": results,
                    "rows": build_summary_rows(results),
                    "paths": {
                        "raw": str(path),
                        "csv": str(RESULT_CSV / f"run_{run_id}.csv"),
                        "markdown": str(RESULT_REPORT / f"run_{run_id}.md"),
                    },
                }
                self.tasks[run_id] = task
            except (OSError, ValueError, TypeError):
                continue

    def safe_json_export(self, task_id: str) -> str:
        task = self.get_task(task_id)
        if not task:
            raise KeyError(task_id)
        return json.dumps({"task": {k: v for k, v in task.items() if k != "rows"}, "results": task["rows"]}, ensure_ascii=False, indent=2)
