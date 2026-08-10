import csv
import copy
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
MAX_PUBLIC_IMPORT_NODES = 10000


def safe_node(node: Dict[str, Any]) -> Dict[str, Any]:
    display_server = node.get("_display_server") or node.get("server")
    display_sni = node.get("sni")
    display_host = node.get("host")
    if node.get("_display_server"):
        if display_sni == display_server:
            display_sni = "(same as server)"
        if display_host == display_server:
            display_host = "(same as server)"
    return {
        "node_id": node.get("_selection_id"),
        "remark": node.get("remark"),
        "protocol": node.get("protocol"),
        "server": display_server,
        "server_port": node.get("server_port"),
        "network": node.get("network"),
        "tls_mode": node.get("tls_mode"),
        "sni": display_sni,
        "host": display_host,
        "path": "(configured)" if node.get("_display_server") and node.get("path") else node.get("path"),
        "source_type": node.get("source_type"),
        "source_name": node.get("source_name"),
        "subscription_name": node.get("subscription_name"),
        "parse_error": node.get("parse_error"),
        "_cloud_redacted": bool(node.get("_display_server")),
    }


def protocol_counts(nodes: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for node in nodes:
        proto = (node.get("protocol") or "unknown").lower()
        counts[proto] = counts.get(proto, 0) + 1
    return counts


class TaskManager:
    def __init__(
        self,
        history_limit: Optional[int] = None,
        *,
        persistent: bool = True,
        runtime_settings: Optional[Dict[str, Any]] = None,
        max_import_nodes: int = MAX_PUBLIC_IMPORT_NODES,
        max_task_nodes: Optional[int] = None,
        max_concurrency: int = 8,
    ):
        ensure_project_dirs()
        self.imports: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self._cancel: Dict[str, threading.Event] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._lock = threading.RLock()
        self.persistent = persistent
        self.runtime_settings = runtime_settings
        self.max_import_nodes = max(1, min(int(max_import_nodes), MAX_PUBLIC_IMPORT_NODES))
        self.max_task_nodes = max_task_nodes
        self.max_concurrency = max(1, min(int(max_concurrency), 8))
        configured_limit = history_limit if history_limit is not None else load_settings().get("history_limit", 10)
        self.history_limit = max(1, min(int(configured_limit or 10), 100))
        if self.persistent:
            self.reload_history(self.history_limit)

    def add_import(self, nodes: List[Dict[str, Any]], source_label: str) -> Dict[str, Any]:
        import_id = uuid.uuid4().hex[:12]
        for index, node in enumerate(nodes):
            node["_selection_id"] = f"n{index + 1:05d}"
        cloud_mode = not self.persistent
        record = {
            "id": import_id,
            "source_label": "cloud import" if cloud_mode else source_label,
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
            output["preview"] = [safe_node(node) for node in nodes[:self.max_import_nodes]]
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
        if spec.get("authorization_confirmed") is not True:
            raise ValueError("请先确认：待测节点由本人所有或已取得明确测试授权")
        imported, selected = self._select_nodes(spec)
        if self.max_task_nodes is not None and len(selected) > self.max_task_nodes:
            raise ValueError(f"Cloud tasks are limited to {self.max_task_nodes} nodes")
        return self._start_selected_task(spec, imported, selected)

    def _select_nodes(self, spec: Dict[str, Any]):
        imported = self.get_import(str(spec.get("import_id") or ""))
        if not imported:
            raise ValueError("Imported node set not found; please import nodes again")
        protocols = [str(x).lower() for x in spec.get("protocols") or []]
        requested_ids = {str(value) for value in (spec.get("node_ids") or []) if value}
        if requested_ids:
            selected = [node for node in imported["nodes"] if node.get("_selection_id") in requested_ids]
        else:
            selected = filter_nodes(
                imported["nodes"],
                filter_substring=str(spec.get("search") or ""),
                protocols=protocols,
                limit=int(spec.get("limit") or 0) or None,
            )
        if not selected:
            raise ValueError("No nodes match the current filters")
        return imported, selected

    def selection_count(self, spec: Dict[str, Any]) -> int:
        _imported, selected = self._select_nodes(spec)
        return len(selected)

    def _start_selected_task(self, spec: Dict[str, Any], imported: Dict[str, Any], selected: List[Dict[str, Any]]) -> Dict[str, Any]:
        kernel = str(spec.get("kernel") or "sing-box")
        task_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        providers = [p for p in (spec.get("providers") or DEFAULT_PROVIDERS) if p in set(DEFAULT_PROVIDERS) | {"abuseipdb"}]
        services = [s for s in (spec.get("service_targets") or []) if s in SERVICE_TARGETS]
        task = {
            "id": task_id,
            "name": str(spec.get("name") or "").strip(),
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
            "protocols": protocol_counts(selected),
            "settings": {
                "authorization_confirmed": True,
                "compliance_notice_version": "2026-08-10",
                "timeout": max(4, min(int(spec.get("timeout") or 15), 90)),
                "concurrency": max(1, min(int(spec.get("concurrency") or 2), self.max_concurrency)),
                "providers": providers,
                "service_targets": services,
                "quality_samples": max(0, min(int(spec.get("quality_samples", 2)), 5)),
            },
            "events": [],
            "results": [],
            "rows": [],
            "paths": {},
            "nodes": selected,
            "_runtime_config": copy.deepcopy(self.runtime_settings) if self.runtime_settings is not None else None,
        }
        cancel = threading.Event()
        with self._lock:
            self.tasks[task_id] = task
            self._cancel[task_id] = cancel
            worker = threading.Thread(
                target=self._run_task,
                args=(task_id,),
                daemon=True,
                name=f"proxy-audit-{task_id}",
            )
            self._threads[task_id] = worker
        worker.start()
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
                    task.get("_runtime_config"),
                    not self.persistent,
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
            if self.persistent:
                self._persist(task)
            else:
                self._redact_in_memory(task)
            task.pop("nodes", None)
            task.pop("_runtime_config", None)
            self._threads.pop(task_id, None)

    def _redact_in_memory(self, task: Dict[str, Any]) -> None:
        safe_results = []
        for item in task["results"]:
            safe_item = dict(item)
            safe_item["node"] = safe_node(item.get("node") or {})
            safe_item.pop("log_tail", None)
            safe_item["config_path"] = None
            safe_item["log_path"] = None
            safe_results.append(safe_item)
        task["results"] = safe_results
        task["rows"] = build_summary_rows(safe_results)
        task["paths"] = {}

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
            "name": task.get("name") or "",
            "source_label": task["source_label"],
            "kernel": task["kernel"],
            "protocols": task.get("protocols") or {},
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
            "id", "name", "status", "source_label", "kernel", "protocols", "created_at", "started_at", "finished_at",
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

    def rename_task(self, task_id: str, name: str) -> Dict[str, Any]:
        clean = re.sub(r"[\x00-\x1f\x7f]", "", str(name or "")).strip()
        if not clean:
            raise ValueError("Task name cannot be empty")
        if len(clean) > 80:
            raise ValueError("Task name must be 80 characters or fewer")
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                raise KeyError(task_id)
            task["name"] = clean
            raw_path_value = (task.get("paths") or {}).get("raw")
            raw_path = Path(raw_path_value) if raw_path_value else None
            if self.persistent and raw_path and raw_path.exists():
                payload = json.loads(raw_path.read_text(encoding="utf-8"))
                payload["name"] = clean
                temp = raw_path.with_suffix(".tmp")
                temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                temp.replace(raw_path)
            return self.public_task(task)

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
                    "name": payload.get("name") or "",
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
                    "protocols": payload.get("protocols") or protocol_counts([
                        item.get("node") or {} for item in results
                    ]),
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

    def cancel_all(self) -> None:
        with self._lock:
            for event in self._cancel.values():
                event.set()

    def clear(self) -> None:
        self.cancel_all()
        with self._lock:
            active_threads = [thread for thread in self._threads.values() if thread.is_alive()]
        if active_threads:
            threading.Thread(
                target=self._clear_after_threads,
                args=(active_threads,),
                daemon=True,
                name="proxy-audit-deferred-clear",
            ).start()
            return
        self._clear_data()

    def _clear_after_threads(self, threads: List[threading.Thread]) -> None:
        for worker in threads:
            worker.join()
        self._clear_data()

    def _clear_data(self) -> None:
        with self._lock:
            for imported in self.imports.values():
                for node in imported.get("nodes") or []:
                    node.clear()
            for task in self.tasks.values():
                runtime_config = task.get("_runtime_config")
                if isinstance(runtime_config, dict):
                    runtime_config.clear()
                for node in task.get("nodes") or []:
                    node.clear()
                for result in task.get("results") or []:
                    node = result.get("node")
                    if isinstance(node, dict):
                        node.clear()
            self.imports.clear()
            self.tasks.clear()
            self._cancel.clear()
            self._threads.clear()

    def safe_json_export(self, task_id: str) -> str:
        task = self.get_task(task_id)
        if not task:
            raise KeyError(task_id)
        return json.dumps({"task": {k: v for k, v in task.items() if k != "rows"}, "results": task["rows"]}, ensure_ascii=False, indent=2)
