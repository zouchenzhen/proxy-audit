import io
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cloud_app
import lib_tasks
from lib_cloud_security import pin_public_node, resolve_public_host
from lib_secrets import decode_scamalytics_credential
from lib_tasks import TaskManager, safe_node
from lib_v2rayn import extract_backup_and_get_db


UUID = "00000000-0000-0000-0000-000000000099"


class CloudApiTests(unittest.TestCase):
    def setUp(self):
        self.clock = [1_000.0]
        self.store = cloud_app.CloudSessionStore(now_fn=lambda: self.clock[0], ttl_seconds=600)
        self.client = cloud_app.create_app(testing=True, session_store=self.store).test_client()

    def session(self):
        response = self.client.post("/api/session")
        self.assertEqual(response.status_code, 201)
        return response.get_json()["token"]

    @staticmethod
    def headers(token):
        return {cloud_app.SESSION_HEADER: token}

    def import_public(self, token, count=1):
        links = "\n".join(
            f"{'vless' + '://'}{UUID}@node-{index}.example:443?security=tls#Node-{index}"
            for index in range(count)
        )
        with patch.object(cloud_app, "pin_public_node", side_effect=lambda node: {
            **node,
            "_display_server": node["server"],
            "server": "93.184.216.34",
        }):
            response = self.client.post(
                "/api/import",
                headers=self.headers(token),
                data={"source_type": "paste", "content": links},
            )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_sessions_isolate_keys_and_imports(self):
        first, second = self.session(), self.session()
        synthetic_value = "session-one-" + "private-key"
        saved = self.client.put(
            "/api/settings",
            headers=self.headers(first),
            json={"updates": {"ipinfo_api_key": [synthetic_value]}},
        )
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.get_json()["key_counts"]["ipinfo_api_key"], 1)
        self.assertNotIn(synthetic_value, saved.get_data(as_text=True))
        other = self.client.get("/api/settings", headers=self.headers(second)).get_json()
        self.assertEqual(other["key_counts"]["ipinfo_api_key"], 0)
        self.import_public(first)
        self.assertEqual(len(self.client.get("/api/imports", headers=self.headers(first)).get_json()["imports"]), 1)
        self.assertEqual(self.client.get("/api/imports", headers=self.headers(second)).get_json()["imports"], [])

    def test_scamalytics_pairs_are_saved_together_without_api_echo(self):
        token = self.session()
        pairs = [
            {"username": "cloud-scam-user-one", "api_key": "cloud-scam-key-one"},
            {"username": "cloud-scam-user-two", "api_key": "cloud-scam-key-two"},
        ]
        saved = self.client.put(
            "/api/settings",
            headers=self.headers(token),
            json={"updates": {"scamalytics_credentials": pairs}},
        )
        self.assertEqual(saved.status_code, 200)
        public = saved.get_json()
        self.assertEqual(public["key_counts"]["scamalytics_credentials"], 2)
        self.assertNotIn("cloud-scam-user-one", saved.get_data(as_text=True))
        self.assertNotIn("cloud-scam-key-one", saved.get_data(as_text=True))
        stored = self.store.get(token).settings["scamalytics_credentials"]
        self.assertEqual([decode_scamalytics_credential(value) for value in stored], [
            ("cloud-scam-user-one", "cloud-scam-key-one"),
            ("cloud-scam-user-two", "cloud-scam-key-two"),
        ])

    def test_huggingface_origin_is_allowed_and_unrelated_origin_is_denied(self):
        token = self.session()
        allowed = self.client.get(
            "/api/system",
            headers={**self.headers(token), "Origin": "https://zouchenzhen-zcz.hf.space"},
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.headers["Access-Control-Allow-Origin"], "https://zouchenzhen-zcz.hf.space")
        denied = self.client.get(
            "/api/system",
            headers={**self.headers(token), "Origin": "https://example.invalid"},
        )
        self.assertEqual(denied.status_code, 403)

    def test_manual_delete_invalidates_session_and_clears_key(self):
        token = self.session()
        self.client.put(
            "/api/settings",
            headers=self.headers(token),
            json={"updates": {"ipinfo_api_key": ["delete-me"]}},
        )
        session = self.store.get(token)
        response = self.client.delete("/api/session", headers=self.headers(token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(session.settings, {})
        self.assertEqual(self.client.get("/api/session", headers=self.headers(token)).status_code, 401)

    def test_expired_session_is_hidden_and_destroyed(self):
        token = self.session()
        session = self.store.get(token)
        session.settings["ipinfo_api_key"] = ["expire-me"]
        self.clock[0] += 601
        self.assertEqual(self.client.get("/api/session", headers=self.headers(token)).status_code, 401)
        self.assertEqual(session.settings, {})
        self.assertEqual(self.store.sessions, {})

    def test_private_node_and_subscription_targets_are_rejected(self):
        token = self.session()
        node = self.client.post(
            "/api/import",
            headers=self.headers(token),
            data={"source_type": "paste", "content": f"{'vless' + '://'}{UUID}@127.0.0.1:443#Private"},
        )
        self.assertEqual(node.status_code, 400)
        subscription = self.client.post(
            "/api/import",
            headers=self.headers(token),
            data={"source_type": "url", "url": "http://169.254.169.254/latest/meta-data"},
        )
        self.assertEqual(subscription.status_code, 400)

    def test_display_address_is_preserved_while_connection_ip_is_pinned(self):
        node = {"server": "edge.example", "server_port": 443, "network": "ws"}
        with patch("lib_cloud_security.resolve_public_host", return_value=["93.184.216.34"]):
            pinned = pin_public_node(node)
        self.assertEqual(pinned["server"], "93.184.216.34")
        self.assertEqual(safe_node(pinned)["server"], "edge.example")
        self.assertEqual(pinned["sni"], "edge.example")
        self.assertEqual(pinned["host"], "edge.example")
        row = lib_tasks.build_summary_rows([{
            "kernel": "sing-box",
            "supported": True,
            "success": False,
            "node": safe_node({**pinned, "path": "/private-subscription-path", "source_name": "secret-source"}),
        }])[0]
        self.assertIsNone(row["path"])
        self.assertIsNone(row["source_name"])

    def test_active_task_limit_is_global(self):
        tokens = [self.session() for _ in range(3)]
        imports = [self.import_public(token) for token in tokens]
        payload = lambda imported: {
            "import_id": imported["id"],
            "authorization_confirmed": True,
            "providers": ["ip_api"],
        }
        with patch.object(lib_tasks.threading.Thread, "start", return_value=None):
            first = self.client.post("/api/tasks", headers=self.headers(tokens[0]), json=payload(imports[0]))
            second = self.client.post("/api/tasks", headers=self.headers(tokens[1]), json=payload(imports[1]))
            third = self.client.post("/api/tasks", headers=self.headers(tokens[2]), json=payload(imports[2]))
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 202)
        self.assertEqual(third.status_code, 503)

    def test_new_tasks_are_rejected_near_expiry(self):
        token = self.session()
        imported = self.import_public(token)
        self.clock[0] += 511
        response = self.client.post(
            "/api/tasks",
            headers=self.headers(token),
            json={"import_id": imported["id"], "authorization_confirmed": True},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("expiry", response.get_json()["error"])

    def test_deleted_session_object_cannot_start_a_racing_task(self):
        token = self.session()
        session = self.store.get(token)
        imported = self.import_public(token)
        self.store.delete(token)
        with self.assertRaisesRegex(ValueError, "expired or deleted"):
            self.store.start_task(session, {
                "import_id": imported["id"],
                "authorization_confirmed": True,
            })


class CloudPersistenceTests(unittest.TestCase):
    def test_ephemeral_manager_does_not_write_result_history(self):
        result = {
            "index": 1,
            "kernel": "sing-box",
            "supported": True,
            "success": True,
            "cancelled": False,
            "skip_reason": "",
            "error": None,
            "node": {},
            "result": {"ipify": {"ip": "203.0.113.8"}},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, csv_dir, reports = root / "raw", root / "csv", root / "reports"
            raw.mkdir(); csv_dir.mkdir(); reports.mkdir()
            manager = TaskManager(persistent=False, runtime_settings={"ipinfo_api_key": ["memory-only"]})
            imported = manager.add_import([
                {"remark": "ephemeral", "protocol": "vless", "server": "93.184.216.34", "server_port": 443, "uuid": UUID}
            ], "cloud test")
            with patch.object(lib_tasks, "RESULT_RAW", raw), patch.object(lib_tasks, "RESULT_CSV", csv_dir), patch.object(lib_tasks, "RESULT_REPORT", reports), patch.object(lib_tasks, "run_node", side_effect=lambda node, *args, **kwargs: {**result, "node": node}):
                task = manager.start_task({"import_id": imported["id"], "authorization_confirmed": True})
                deadline = time.time() + 3
                while manager.get_task(task["id"])["status"] not in {"completed", "cancelled"} and time.time() < deadline:
                    time.sleep(0.01)
            finished = manager.get_task(task["id"])
            self.assertEqual(finished["status"], "completed")
            self.assertEqual(list(root.rglob("*.*")), [])
            self.assertNotIn(UUID, repr(finished))
            self.assertNotIn("memory-only", repr(manager.tasks[task["id"]]))


class ZipSafetyTests(unittest.TestCase):
    def _zip(self, root: Path, members):
        path = root / "backup.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, body in members:
                archive.writestr(name, body)
        return path

    def test_zip_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._zip(root, [("../guiNDB.db", b"not-a-db")])
            with self.assertRaisesRegex(ValueError, "Unsafe path"):
                extract_backup_and_get_db(path, extract_dir=root / "out", max_files=10, max_uncompressed_bytes=1024)

    def test_zip_file_count_and_expanded_size_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._zip(root, [("a", b"1"), ("guiNDB.db", b"2")])
            with self.assertRaisesRegex(ValueError, "more than"):
                extract_backup_and_get_db(path, extract_dir=root / "many", max_files=1, max_uncompressed_bytes=1024)
            with self.assertRaisesRegex(ValueError, "safety limit"):
                extract_backup_and_get_db(path, extract_dir=root / "large", max_files=10, max_uncompressed_bytes=1)

    def test_public_address_policy_blocks_non_global_ranges(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "fe80::1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                resolve_public_host(address, 443)


if __name__ == "__main__":
    unittest.main()
