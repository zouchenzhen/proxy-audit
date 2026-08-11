import argparse
import csv
import hashlib
import io
import json
import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from lib_cloud_security import fetch_public_subscription, pin_public_node
from lib_ipintel import DEFAULT_PROVIDERS, PROVIDER_META, SERVICE_TARGETS
from lib_kernels import kernel_catalog
from lib_paths import WEB_DIR
from lib_secrets import (
    SCAMALYTICS_CREDENTIALS_FIELD,
    SECRET_FIELDS,
    normalize_secret_field,
    normalize_secret_values,
    scamalytics_credential_previews,
    secret_id,
    secret_preview,
)
from lib_tasks import TaskManager
from lib_v2rayn import load_from_input_file, load_from_text, load_from_v2ray_backup, load_from_v2ray_db


OFFICIAL_UI_ORIGIN = os.environ.get("PROXY_AUDIT_UI_ORIGIN", "https://zouchenzhen-zcz.hf.space").rstrip("/")
SESSION_TTL_SECONDS = 3600
MAX_SESSIONS = 200
MAX_IMPORT_NODES = 20
MAX_TASK_NODES = 20
MAX_CONCURRENCY = 2
MAX_ACTIVE_TASKS = 2
MAX_DAILY_NODES_PER_CLIENT = 100
MAX_SESSION_CREATIONS_PER_HOUR = 10
MAX_UPLOAD_BYTES = 4 * 1024 * 1024
MAX_KEYS_PER_PROVIDER = 10
MAX_ZIP_FILES = 250
MAX_ZIP_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
SESSION_HEADER = "X-Proxy-Audit-Session"
ACTIVE_STATES = {"queued", "running", "cancelling"}
MAX_CLOUD_REQUEST_TIMEOUT = 12
NEW_TASK_CUTOFF_SECONDS = 90


def _now() -> float:
    return time.time()


def _public_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    previews = {
        field_name: (
            scamalytics_credential_previews(settings.get(field_name))
            if field_name == SCAMALYTICS_CREDENTIALS_FIELD
            else [secret_preview(value) for value in normalize_secret_values(settings.get(field_name))]
        )
        for field_name in sorted(SECRET_FIELDS)
    }
    return {
        "configured": {field_name: bool(previews[field_name]) for field_name in previews},
        "key_counts": {field_name: len(previews[field_name]) for field_name in previews},
        "key_previews": previews,
        "scamalytics_user_configured": bool(previews.get(SCAMALYTICS_CREDENTIALS_FIELD)),
        "singbox_path": "",
        "xray_path": "",
        "default_timeout": max(4, min(int(settings.get("default_timeout") or 15), 30)),
        "default_concurrency": max(1, min(int(settings.get("default_concurrency") or 2), MAX_CONCURRENCY)),
        "history_limit": 10,
        "storage": "云端临时内存（最长 1 小时）",
        "legacy_config_detected": False,
    }


def _update_settings(settings: Dict[str, Any], payload: Dict[str, Any]) -> None:
    updates = payload.get("updates") or {}
    clear_fields = {str(value) for value in payload.get("clear_fields") or []}
    remove_ids = payload.get("remove_key_ids") or {}
    for field_name in SECRET_FIELDS:
        if field_name in clear_fields:
            settings[field_name] = []
        remove = {str(value) for value in remove_ids.get(field_name) or []}
        if remove:
            settings[field_name] = [
                key for key in normalize_secret_field(field_name, settings.get(field_name)) if secret_id(key) not in remove
            ]
        if field_name in updates:
            merged = normalize_secret_field(field_name, settings.get(field_name)) + normalize_secret_field(field_name, updates[field_name])
            settings[field_name] = normalize_secret_field(field_name, merged)[:MAX_KEYS_PER_PROVIDER]
    if "default_timeout" in updates:
        settings["default_timeout"] = max(4, min(int(updates["default_timeout"]), 30))
    if "default_concurrency" in updates:
        settings["default_concurrency"] = max(1, min(int(updates["default_concurrency"]), MAX_CONCURRENCY))


@dataclass
class CloudSession:
    session_id: str
    client_hash: str
    created_at: float
    expires_at: float
    manager: TaskManager
    settings: Dict[str, Any] = field(default_factory=lambda: {
        "default_timeout": 15,
        "default_concurrency": 2,
    })
    destroyed: bool = False

    def public(self) -> Dict[str, Any]:
        return {
            "id": self.session_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "ttl_seconds": max(0, int(self.expires_at - _now())),
        }

    def destroy(self) -> None:
        self.destroyed = True
        self.expires_at = min(self.expires_at, _now())
        for value in self.settings.values():
            if isinstance(value, list):
                value.clear()
        self.settings.clear()
        self.manager.clear()


class CloudSessionStore:
    def __init__(self, *, now_fn=_now, ttl_seconds: int = SESSION_TTL_SECONDS):
        self.now = now_fn
        self.ttl_seconds = ttl_seconds
        self.sessions: Dict[str, CloudSession] = {}
        self.creation_windows: Dict[str, list] = {}
        self.daily_usage: Dict[tuple, int] = {}
        self._salt = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._reaper_started = False

    def start_reaper(self) -> None:
        with self._lock:
            if self._reaper_started:
                return
            self._reaper_started = True
        threading.Thread(target=self._reaper_loop, daemon=True, name="proxy-audit-session-reaper").start()

    def _reaper_loop(self) -> None:
        while True:
            time.sleep(1)
            with self._lock:
                self.prune_locked(self.now())

    def client_hash(self, value: str) -> str:
        return hashlib.sha256(self._salt + str(value or "unknown").encode("utf-8", errors="ignore")).hexdigest()

    def create(self, client_value: str) -> tuple[str, CloudSession]:
        now = self.now()
        client_hash = self.client_hash(client_value)
        with self._lock:
            self.prune_locked(now)
            recent = [stamp for stamp in self.creation_windows.get(client_hash, []) if stamp > now - 3600]
            if len(recent) >= MAX_SESSION_CREATIONS_PER_HOUR:
                raise ValueError("Too many sessions created; please reuse the current browser session")
            if len(self.sessions) >= MAX_SESSIONS:
                raise RuntimeError("Cloud service is at capacity; please try again later")
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            session_id = uuid.uuid4().hex[:12]
            settings = {"default_timeout": 15, "default_concurrency": 2}
            manager = TaskManager(
                history_limit=10,
                persistent=False,
                runtime_settings=settings,
                max_import_nodes=MAX_IMPORT_NODES,
                max_task_nodes=MAX_TASK_NODES,
                max_concurrency=MAX_CONCURRENCY,
            )
            session = CloudSession(session_id, client_hash, now, now + self.ttl_seconds, manager, settings)
            self.sessions[token_hash] = session
            recent.append(now)
            self.creation_windows[client_hash] = recent
            return token, session

    def get(self, token: str) -> Optional[CloudSession]:
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()
        with self._lock:
            self.prune_locked(self.now())
            session = self.sessions.get(token_hash)
            if not session or session.destroyed or session.expires_at <= self.now():
                return None
            return session

    def delete(self, token: str) -> bool:
        token_hash = hashlib.sha256(str(token or "").encode("utf-8", errors="ignore")).hexdigest()
        with self._lock:
            session = self.sessions.pop(token_hash, None)
            if session:
                session.destroy()
                return True
            return False

    def prune_locked(self, now: float) -> None:
        expired = [key for key, session in self.sessions.items() if session.expires_at <= now]
        for key in expired:
            session = self.sessions.pop(key)
            session.destroy()
        old_days = [key for key in self.daily_usage if key[0] != time.strftime("%Y-%m-%d", time.gmtime(now))]
        for key in old_days:
            self.daily_usage.pop(key, None)
        for key, stamps in list(self.creation_windows.items()):
            recent = [stamp for stamp in stamps if stamp > now - 3600]
            if recent:
                self.creation_windows[key] = recent
            else:
                self.creation_windows.pop(key, None)

    def start_task(self, session: CloudSession, spec: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if session.destroyed or session.expires_at <= self.now():
                raise ValueError("Cloud session is expired or deleted")
            if session.expires_at - self.now() <= NEW_TASK_CUTOFF_SECONDS:
                raise ValueError("Cloud session is too close to expiry; create a new session first")
            active = sum(
                1
                for item in self.sessions.values()
                for task in item.manager.tasks.values()
                if task.get("status") in ACTIVE_STATES
            )
            if active >= MAX_ACTIVE_TASKS:
                raise RuntimeError("Cloud service is busy; at most two tasks can run at once")
            count = session.manager.selection_count(spec)
            day = time.strftime("%Y-%m-%d", time.gmtime(self.now()))
            usage_key = (day, session.client_hash)
            used = self.daily_usage.get(usage_key, 0)
            if used + count > MAX_DAILY_NODES_PER_CLIENT:
                raise ValueError("Daily cloud quota reached for this network")
            session.manager.runtime_settings = session.settings
            task = session.manager.start_task(spec)
            self.daily_usage[usage_key] = used + count
            return task


store = CloudSessionStore()


def _client_address() -> str:
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
    return request.headers.get("CF-Connecting-IP") or forwarded or request.remote_addr or "unknown"


def _token() -> str:
    return request.headers.get(SESSION_HEADER, "").strip()


def _dedupe_and_pin(nodes) -> list:
    if len(nodes) > MAX_IMPORT_NODES:
        raise ValueError(f"Cloud imports are limited to {MAX_IMPORT_NODES} nodes; use the local edition for larger batches")
    output = []
    seen = set()
    errors = []
    for node in nodes[:MAX_IMPORT_NODES]:
        try:
            pinned = pin_public_node(node)
        except (ValueError, TypeError) as error:
            errors.append(str(error))
            continue
        identity = (
            pinned.get("protocol"), pinned.get("server"), pinned.get("server_port"),
            pinned.get("uuid") or pinned.get("password"), pinned.get("path"), pinned.get("sni"),
        )
        if identity not in seen:
            seen.add(identity)
            output.append(pinned)
    if not output:
        raise ValueError(errors[0] if errors else "No recognizable public node links found")
    return output


def create_app(testing: bool = False, session_store: Optional[CloudSessionStore] = None) -> Flask:
    sessions = session_store or store
    if not testing:
        sessions.start_reaper()
    app = Flask(__name__, static_folder=None)
    app.config.update(TESTING=testing, MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES, JSON_AS_ASCII=False)

    @app.before_request
    def require_official_origin_and_session():
        if not request.path.startswith("/api/"):
            return None
        origin = request.headers.get("Origin")
        same_origin = request.host_url.rstrip("/")
        if origin and origin.rstrip("/") not in {OFFICIAL_UI_ORIGIN, same_origin}:
            return jsonify({"error": "Origin is not allowed"}), 403
        if request.method == "OPTIONS":
            return Response(status=204)
        if request.path == "/api/health" and request.method == "GET":
            return None
        if request.path == "/api/session" and request.method == "POST":
            return None
        session = sessions.get(_token())
        if not session:
            return jsonify({"error": "Cloud session is missing or expired"}), 401
        request.cloud_session = session
        return None

    @app.after_request
    def response_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'self' https://huggingface.co; object-src 'none'"
        )
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") in {OFFICIAL_UI_ORIGIN, request.host_url.rstrip("/")}:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = f"Content-Type, {SESSION_HEADER}"
            response.headers["Vary"] = "Origin"
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"error": "Cloud uploads are limited to 4 MB"}), 413

    @app.errorhandler(Exception)
    def api_error(error):
        if not request.path.startswith("/api/"):
            return error
        status = getattr(error, "code", 500)
        if isinstance(error, ValueError):
            status = 400
        message = str(error) if status < 500 else "Cloud service error"
        app.logger.exception("cloud API error") if status >= 500 else None
        return jsonify({"error": message}), status

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "mode": "cloud-ephemeral", "version": "2.3.0", "ttl_seconds": SESSION_TTL_SECONDS})

    @app.get("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.get("/legal")
    def legal():
        return send_from_directory(WEB_DIR, "legal.html")

    @app.get("/favicon.ico")
    def favicon():
        return Response(status=204)

    @app.get("/static/<path:asset>")
    def static_asset(asset):
        return send_from_directory(WEB_DIR, asset)

    @app.post("/api/session")
    def create_session():
        try:
            token, session = sessions.create(_client_address())
        except ValueError as error:
            return jsonify({"error": str(error)}), 429
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503
        return jsonify({"token": token, "session": session.public()}), 201

    @app.get("/api/session")
    def get_session():
        return jsonify({"session": request.cloud_session.public()})

    @app.delete("/api/session")
    def delete_session():
        sessions.delete(_token())
        return jsonify({"deleted": True})

    @app.get("/api/system")
    def system_info():
        session = request.cloud_session
        kernels = []
        for item in kernel_catalog():
            public = dict(item)
            public["path"] = "cloud-managed"
            kernels.append(public)
        return jsonify({
            "mode": "cloud-ephemeral",
            "session": session.public(),
            "limits": {
                "max_import_nodes": MAX_IMPORT_NODES,
                "max_nodes_per_task": MAX_TASK_NODES,
                "max_concurrency": MAX_CONCURRENCY,
                "max_daily_nodes": MAX_DAILY_NODES_PER_CLIENT,
                "max_keys_per_provider": MAX_KEYS_PER_PROVIDER,
            },
            "kernels": kernels,
            "providers": PROVIDER_META,
            "services": [{"id": key, "name": value[0]} for key, value in SERVICE_TARGETS.items()],
            "settings": _public_settings(session.settings),
        })

    @app.get("/api/settings")
    def get_settings():
        return jsonify(_public_settings(request.cloud_session.settings))

    @app.put("/api/settings")
    def put_settings():
        _update_settings(request.cloud_session.settings, request.get_json(force=True) or {})
        return jsonify(_public_settings(request.cloud_session.settings))

    @app.get("/api/imports")
    def list_imports():
        return jsonify({"imports": request.cloud_session.manager.list_imports()})

    @app.get("/api/imports/<import_id>")
    def get_import(import_id):
        imported = request.cloud_session.manager.get_public_import(import_id)
        return jsonify(imported) if imported else (jsonify({"error": "Import not found"}), 404)

    @app.post("/api/import")
    def import_nodes():
        source_type = (request.form.get("source_type") or "paste").lower()
        if source_type == "paste":
            content = request.form.get("content") or ""
            if not content.strip():
                return jsonify({"error": "No node links supplied"}), 400
            if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
                return jsonify({"error": "Pasted content exceeds 4 MB"}), 413
            nodes = load_from_text(content, "cloud-paste")
            label = "pasted links"
        elif source_type == "url":
            content = fetch_public_subscription(request.form.get("url") or "")
            nodes = load_from_text(content, "cloud-subscription")
            label = "subscription URL"
        elif source_type == "file":
            uploaded = request.files.get("file")
            if not uploaded or not uploaded.filename:
                return jsonify({"error": "No file selected"}), 400
            name = secure_filename(uploaded.filename) or "nodes.txt"
            suffix = Path(name).suffix.lower()
            from tempfile import TemporaryDirectory
            with TemporaryDirectory(prefix="proxy-audit-cloud-upload-") as temp_dir:
                path = Path(temp_dir) / name
                uploaded.save(path)
                if suffix == ".zip":
                    nodes = load_from_v2ray_backup(
                        str(path),
                        extract_dir=Path(temp_dir) / "extracted",
                        max_files=MAX_ZIP_FILES,
                        max_uncompressed_bytes=MAX_ZIP_UNCOMPRESSED_BYTES,
                    )
                elif suffix in {".db", ".sqlite", ".sqlite3"}:
                    nodes = load_from_v2ray_db(str(path))
                else:
                    nodes = load_from_input_file(str(path))
            label = f"uploaded file: {name}"
        else:
            return jsonify({"error": "Unsupported import type"}), 400
        return jsonify(request.cloud_session.manager.add_import(_dedupe_and_pin(nodes), label))

    @app.get("/api/tasks")
    def list_tasks():
        return jsonify({"tasks": request.cloud_session.manager.list_tasks()})

    @app.post("/api/tasks")
    def start_task():
        payload = request.get_json(force=True) or {}
        payload["concurrency"] = min(int(payload.get("concurrency") or 2), MAX_CONCURRENCY)
        payload["timeout"] = min(int(payload.get("timeout") or 12), MAX_CLOUD_REQUEST_TIMEOUT)
        try:
            task = sessions.start_task(request.cloud_session, payload)
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 503
        return jsonify(task), 202

    @app.get("/api/tasks/<task_id>")
    def get_task(task_id):
        task = request.cloud_session.manager.get_task(task_id)
        return jsonify(task) if task else (jsonify({"error": "Task not found"}), 404)

    @app.post("/api/tasks/<task_id>/cancel")
    def cancel_task(task_id):
        try:
            return jsonify(request.cloud_session.manager.cancel_task(task_id))
        except KeyError:
            return jsonify({"error": "Task not found"}), 404

    @app.patch("/api/tasks/<task_id>")
    def rename_task(task_id):
        try:
            return jsonify(request.cloud_session.manager.rename_task(task_id, (request.get_json(force=True) or {}).get("name") or ""))
        except KeyError:
            return jsonify({"error": "Task not found"}), 404

    @app.get("/api/tasks/<task_id>/export")
    def export_task(task_id):
        task = request.cloud_session.manager.get_task(task_id)
        if not task:
            return jsonify({"error": "Task not found"}), 404
        fmt = (request.args.get("format") or "csv").lower()
        rows = task.get("rows") or []
        if fmt == "json":
            body = request.cloud_session.manager.safe_json_export(task_id)
            mime, ext = "application/json; charset=utf-8", "json"
        elif fmt == "csv":
            stream = io.StringIO(newline="")
            fields = list(dict.fromkeys(key for row in rows for key in row.keys())) or ["no_data"]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
            body, mime, ext = "\ufeff" + stream.getvalue(), "text/csv; charset=utf-8", "csv"
        elif fmt in {"md", "markdown"}:
            lines = ["# Proxy Audit Cloud Report", "", f"- task: `{task_id}`", f"- expires_at: `{request.cloud_session.expires_at}`", "", "## Results", ""]
            for index, row in enumerate(rows, 1):
                lines.extend([
                    f"### {index}. {row.get('remark') or '(no remark)'}",
                    f"- protocol: `{row.get('protocol')}`",
                    f"- success: `{row.get('success')}`",
                    f"- exit_ip: `{row.get('exit_ip')}`",
                    f"- type/risk: `{row.get('ip_type_final')} / {row.get('risk_level_final')}`",
                    f"- latency_ms: `{row.get('latency_median_ms')}`",
                    "",
                ])
            body, mime, ext = "\n".join(lines), "text/markdown; charset=utf-8", "md"
        else:
            return jsonify({"error": "Supported formats: csv, json, md"}), 400
        return Response(body, mimetype=mime, headers={"Content-Disposition": f'attachment; filename="proxy-audit-{task_id}.{ext}"'})

    @app.get("/third-party/<path:asset>")
    def third_party(asset):
        root = Path("/opt/proxy-audit/third-party")
        requested = (root / asset).resolve()
        if root.resolve() not in requested.parents or not requested.is_file():
            return jsonify({"error": "Third-party artifact not found"}), 404
        return send_from_directory(requested.parent, requested.name, as_attachment=True)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Proxy Audit ephemeral cloud API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
