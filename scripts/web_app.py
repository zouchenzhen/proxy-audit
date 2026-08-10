import argparse
import json
import threading
import time
import uuid
import webbrowser
from pathlib import Path

import requests
from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from lib_ipintel import PROVIDER_META, SERVICE_TARGETS
from lib_kernels import kernel_catalog
from lib_paths import UPLOAD_DIR, WEB_DIR, ensure_project_dirs
from lib_secrets import public_settings, save_settings
from lib_tasks import TaskManager
from lib_v2rayn import load_from_input_file, load_from_text, load_from_v2ray_backup, load_from_v2ray_db


manager = TaskManager()


def create_app(testing: bool = False) -> Flask:
    ensure_project_dirs()
    app = Flask(__name__, static_folder=str(WEB_DIR), static_url_path="/static")
    app.config.update(MAX_CONTENT_LENGTH=64 * 1024 * 1024, JSON_AS_ASCII=False, TESTING=testing)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
        return response

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"error": "Upload exceeds the 64 MB local limit"}), 413

    @app.errorhandler(Exception)
    def api_error(error):
        if not request.path.startswith("/api/"):
            raise error
        status = getattr(error, "code", 500)
        message = str(error) if status < 500 else f"{type(error).__name__}: {error}"
        return jsonify({"error": message}), status

    @app.get("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "version": "2.1.0", "time": time.time()})

    @app.get("/api/system")
    def system_info():
        return jsonify({
            "kernels": kernel_catalog(),
            "providers": PROVIDER_META,
            "services": [{"id": key, "name": value[0]} for key, value in SERVICE_TARGETS.items()],
            "settings": public_settings(),
        })

    @app.get("/api/settings")
    def get_settings():
        return jsonify(public_settings())

    @app.put("/api/settings")
    def put_settings():
        payload = request.get_json(force=True) or {}
        updates = payload.get("updates") or {}
        clear_fields = payload.get("clear_fields") or []
        remove_key_ids = payload.get("remove_key_ids") or {}
        save_settings(updates, clear_fields, remove_key_ids)
        settings = public_settings()
        manager.reload_history(settings["history_limit"])
        return jsonify(settings)

    @app.get("/api/imports")
    def list_imports():
        return jsonify({"imports": manager.list_imports()})

    @app.get("/api/imports/<import_id>")
    def get_import(import_id):
        imported = manager.get_public_import(import_id)
        return jsonify(imported) if imported else (jsonify({"error": "Import not found"}), 404)

    @app.post("/api/import")
    def import_nodes():
        source_type = (request.form.get("source_type") or "paste").lower()
        if source_type == "paste":
            content = request.form.get("content") or ""
            if not content.strip():
                return jsonify({"error": "No node links supplied"}), 400
            nodes = load_from_text(content, "web-paste")
            label = "pasted links"
        elif source_type == "url":
            url = (request.form.get("url") or "").strip()
            if not url.lower().startswith(("http://", "https://")):
                return jsonify({"error": "Subscription URL must use HTTP or HTTPS"}), 400
            response = requests.get(url, timeout=25, headers={"User-Agent": "ProxyAudit/2.0"})
            response.raise_for_status()
            if len(response.content) > 16 * 1024 * 1024:
                return jsonify({"error": "Subscription response exceeds 16 MB"}), 400
            nodes = load_from_text(response.text, "subscription-url")
            label = "subscription URL"
        elif source_type == "file":
            uploaded = request.files.get("file")
            if not uploaded or not uploaded.filename:
                return jsonify({"error": "No file selected"}), 400
            name = secure_filename(uploaded.filename) or f"upload_{uuid.uuid4().hex[:8]}"
            path = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{name}"
            uploaded.save(path)
            suffix = Path(name).suffix.lower()
            if suffix == ".zip":
                nodes = load_from_v2ray_backup(str(path))
                label = f"v2rayN backup: {name}"
            elif suffix in {".db", ".sqlite", ".sqlite3"}:
                nodes = load_from_v2ray_db(str(path))
                label = f"v2rayN database: {name}"
            else:
                nodes = load_from_input_file(str(path))
                label = f"node file: {name}"
        else:
            return jsonify({"error": f"Unsupported import type: {source_type}"}), 400

        unique = []
        seen = set()
        for node in nodes[:10000]:
            identity = (
                node.get("protocol"), node.get("server"), node.get("server_port"),
                node.get("uuid") or node.get("password"), node.get("path"), node.get("sni"),
            )
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(node)
        if not unique:
            return jsonify({"error": "No recognizable node links found"}), 400
        return jsonify(manager.add_import(unique, label))

    @app.get("/api/tasks")
    def list_tasks():
        return jsonify({"tasks": manager.list_tasks()})

    @app.post("/api/tasks")
    def start_task():
        try:
            return jsonify(manager.start_task(request.get_json(force=True) or {})), 202
        except ValueError as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/tasks/<task_id>")
    def get_task(task_id):
        task = manager.get_task(task_id)
        return jsonify(task) if task else (jsonify({"error": "Task not found"}), 404)

    @app.post("/api/tasks/<task_id>/cancel")
    def cancel_task(task_id):
        try:
            return jsonify(manager.cancel_task(task_id))
        except KeyError:
            return jsonify({"error": "Task not found"}), 404

    @app.patch("/api/tasks/<task_id>")
    def rename_task(task_id):
        try:
            payload = request.get_json(force=True) or {}
            return jsonify(manager.rename_task(task_id, payload.get("name") or ""))
        except KeyError:
            return jsonify({"error": "Task not found"}), 404
        except ValueError as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/tasks/<task_id>/export")
    def export_task(task_id):
        task = manager.get_task(task_id)
        if not task:
            return jsonify({"error": "Task not found"}), 404
        fmt = (request.args.get("format") or "csv").lower()
        if fmt == "json":
            body, mimetype, ext = manager.safe_json_export(task_id), "application/json", "json"
        elif fmt == "csv":
            path = (task.get("paths") or {}).get("csv")
            if not path or not Path(path).exists():
                return jsonify({"error": "CSV is not ready yet"}), 409
            body, mimetype, ext = Path(path).read_text(encoding="utf-8-sig"), "text/csv; charset=utf-8", "csv"
        elif fmt in {"md", "markdown"}:
            path = (task.get("paths") or {}).get("markdown")
            if not path or not Path(path).exists():
                return jsonify({"error": "Markdown report is not ready yet"}), 409
            body, mimetype, ext = Path(path).read_text(encoding="utf-8"), "text/markdown; charset=utf-8", "md"
        else:
            return jsonify({"error": "Supported formats: csv, json, md"}), 400
        return Response(body, mimetype=mimetype, headers={"Content-Disposition": f'attachment; filename="proxy-audit-{task_id}.{ext}"'})

    return app


def main():
    parser = argparse.ArgumentParser(description="Proxy Audit local Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("For safety, the Web UI only binds to localhost")
    if not args.no_open:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{args.port}")).start()
    create_app().run(host=args.host, port=args.port, debug=args.debug, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
