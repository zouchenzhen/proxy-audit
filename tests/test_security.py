import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lib_secrets
import lib_tasks
import lib_ipintel
import scan_git_history
from lib_report import build_summary_rows
from lib_tasks import TaskManager


class SecureSettingsTests(unittest.TestCase):
    def test_history_scanner_detects_secret_without_retaining_value(self):
        secret = "_".join(("SYNTHETIC", "TOKEN", "SHOULD", "BE", "DETECTED", "123"))
        findings = scan_git_history.scan_bytes("worktree", "sample.txt", f'api_key = "{secret}"'.encode())
        self.assertEqual(findings[0][0], "assigned-secret")
        self.assertNotIn(secret, repr(findings))

    def test_save_load_and_clear_legacy_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secure = root / "config.secure.json"
            legacy = root / "config.local.json"
            legacy.write_text(json.dumps({"ipqs_api_key": "legacy-secret"}), encoding="utf-8")
            with patch.object(lib_secrets, "SECURE_CONFIG", secure), patch.object(lib_secrets, "LEGACY_CONFIG", legacy):
                lib_secrets.save_settings({"ipinfo_api_key": "new-secret"})
                loaded = lib_secrets.load_settings()
                self.assertEqual(loaded["ipinfo_api_key"], ["new-secret"])
                self.assertEqual(loaded["ipqs_api_key"], ["legacy-secret"])
                lib_secrets.save_settings({}, clear_fields=["ipqs_api_key"])
                self.assertEqual(lib_secrets.load_settings().get("ipqs_api_key"), [])
                wrapper = secure.read_text(encoding="utf-8")
                self.assertNotIn("new-secret", wrapper)

    def test_multiple_keys_have_safe_previews_and_individual_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            secure = Path(directory) / "config.secure.json"
            legacy = Path(directory) / "config.local.json"
            with patch.object(lib_secrets, "SECURE_CONFIG", secure), patch.object(lib_secrets, "LEGACY_CONFIG", legacy):
                lib_secrets.save_settings({"ipinfo_api_key": ["alpha-secret-111", "beta-secret-222", "alpha-secret-111"]})
                public = lib_secrets.public_settings()
                self.assertEqual(public["key_counts"]["ipinfo_api_key"], 2)
                self.assertNotIn("alpha-secret-111", json.dumps(public))
                first_id = public["key_previews"]["ipinfo_api_key"][0]["id"]
                lib_secrets.save_settings({}, remove_key_ids={"ipinfo_api_key": [first_id]})
                self.assertEqual(lib_secrets.load_settings()["ipinfo_api_key"], ["beta-secret-222"])

    def test_key_pool_rotates_after_rejected_key(self):
        attempts = []
        with lib_ipintel._KEY_POOL_LOCK:
            lib_ipintel._KEY_POOL_CURSOR.clear()
            lib_ipintel._KEY_POOL_COOLDOWN.clear()

        def fetcher(key):
            attempts.append(key)
            if key == "bad-key":
                raise lib_ipintel.ProviderKeyUnavailable("quota")
            return {"ok": True}

        result = lib_ipintel._request_with_key_pool("ipinfo_api_key", {"ipinfo_api_key": ["bad-key", "good-key"]}, fetcher)
        self.assertTrue(result["ok"])
        self.assertEqual(attempts, ["bad-key", "good-key"])

    def test_history_limit_is_bounded_and_public(self):
        with tempfile.TemporaryDirectory() as directory:
            secure = Path(directory) / "config.secure.json"
            legacy = Path(directory) / "config.local.json"
            with patch.object(lib_secrets, "SECURE_CONFIG", secure), patch.object(lib_secrets, "LEGACY_CONFIG", legacy):
                lib_secrets.save_settings({"history_limit": 37})
                self.assertEqual(lib_secrets.public_settings()["history_limit"], 37)

    def test_runtime_environment_keys_override_without_being_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            secure = Path(directory) / "config.secure.json"
            legacy = Path(directory) / "config.local.json"
            legacy.write_text(json.dumps({"ipinfo_api_key": "legacy-secret"}), encoding="utf-8")
            runtime = {
                "PROXY_AUDIT_IPINFO_API_KEY_1": "runtime-one",
                "PROXY_AUDIT_IPINFO_API_KEY_2": "runtime-two",
                "PROXY_AUDIT_SCAMALYTICS_USER": "runtime-user",
            }
            with patch.object(lib_secrets, "SECURE_CONFIG", secure), patch.object(lib_secrets, "LEGACY_CONFIG", legacy):
                with patch.dict(os.environ, runtime, clear=False):
                    loaded = lib_secrets.load_settings()
                    self.assertEqual(loaded["ipinfo_api_key"], ["runtime-one", "runtime-two"])
                    self.assertEqual(loaded["scamalytics_user"], "runtime-user")
                    lib_secrets.save_settings({"history_limit": 22})
                persisted = lib_secrets.load_settings(include_legacy=False)
                self.assertEqual(persisted["ipinfo_api_key"], ["legacy-secret"])
                self.assertNotIn("runtime-one", persisted["ipinfo_api_key"])
                self.assertNotIn("runtime-two", persisted["ipinfo_api_key"])
                self.assertNotIn("scamalytics_user", persisted)
                self.assertEqual(persisted["history_limit"], 22)


class ResultRedactionTests(unittest.TestCase):
    def test_persisted_raw_result_has_no_node_credential(self):
        secret = "00000000-0000-0000-0000-secret-node-credential"
        item = {
            "index": 1,
            "kernel": "sing-box",
            "supported": True,
            "success": True,
            "cancelled": False,
            "skip_reason": "",
            "error": None,
            "node": {
                "remark": "safe node",
                "protocol": "vless",
                "server": "example.com",
                "server_port": 443,
                "uuid": secret,
                "password": secret,
                "subscription_url": "https://subscription.invalid/private",
            },
            "result": {"ipify": {"ip": "203.0.113.1"}, "unified": {"risk_level_final": "low", "risk_score_final": 0}},
            "log_tail": secret,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, csv_dir, reports = root / "raw", root / "csv", root / "reports"
            raw.mkdir(); csv_dir.mkdir(); reports.mkdir()
            manager = TaskManager()
            task = {
                "id": "test_redaction",
                "source_label": "unit test",
                "kernel": "sing-box",
                "settings": {},
                "status": "completed",
                "created_at": 1,
                "finished_at": 2,
                "results": [item],
                "rows": build_summary_rows([item]),
                "paths": {},
            }
            with patch.object(lib_tasks, "RESULT_RAW", raw), patch.object(lib_tasks, "RESULT_CSV", csv_dir), patch.object(lib_tasks, "RESULT_REPORT", reports):
                manager._persist(task)
            payload = (raw / "run_test_redaction.json").read_text(encoding="utf-8")
            self.assertNotIn(secret, payload)
            self.assertNotIn("subscription.invalid", payload)

    def test_recent_tasks_restore_from_redacted_raw_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, csv_dir, reports = root / "raw", root / "csv", root / "reports"
            raw.mkdir(); csv_dir.mkdir(); reports.mkdir()
            payload = {
                "run_id": "20260808_120000_abcdef",
                "source_label": "restored source",
                "kernel": "sing-box",
                "settings": {},
                "status": "completed",
                "created_at": 10,
                "started_at": 11,
                "finished_at": 12,
                "events": [{"time": 12, "level": "info", "message": "完成"}],
                "results": [{
                    "index": 1, "kernel": "sing-box", "supported": True, "success": True,
                    "cancelled": False, "skip_reason": "", "error": None,
                    "node": {"remark": "safe", "protocol": "vless", "server": "example.com", "server_port": 443},
                    "result": {"ipify": {"ip": "203.0.113.1"}},
                }],
            }
            (raw / "run_20260808_120000_abcdef.json").write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(lib_tasks, "RESULT_RAW", raw), patch.object(lib_tasks, "RESULT_CSV", csv_dir), patch.object(lib_tasks, "RESULT_REPORT", reports):
                manager = TaskManager(history_limit=10)
                restored = manager.get_task("20260808_120000_abcdef")
                renamed = manager.rename_task("20260808_120000_abcdef", "晚间复测")
            self.assertIsNotNone(restored)
            self.assertEqual(restored["success"], 1)
            self.assertEqual(restored["rows"][0]["remark"], "safe")
            self.assertEqual(renamed["name"], "晚间复测")
            self.assertEqual(json.loads((raw / "run_20260808_120000_abcdef.json").read_text(encoding="utf-8"))["name"], "晚间复测")

    def test_explicit_node_selection_only_starts_selected_nodes(self):
        manager = TaskManager(history_limit=1)
        imported = manager.add_import([
            {"remark": "one", "protocol": "vless", "server": "one.invalid", "server_port": 443},
            {"remark": "two", "protocol": "trojan", "server": "two.invalid", "server_port": 443},
        ], "selection test")
        selected_id = imported["preview"][1]["node_id"]
        with patch.object(lib_tasks.threading.Thread, "start", return_value=None):
            task = manager.start_task({"import_id": imported["id"], "node_ids": [selected_id], "providers": ["ip_api"], "authorization_confirmed": True})
        self.assertEqual(task["total"], 1)
        self.assertEqual(task["protocols"], {"trojan": 1})

    def test_task_requires_explicit_authorization_confirmation(self):
        manager = TaskManager(history_limit=1)
        imported = manager.add_import([
            {"remark": "owned", "protocol": "vless", "server": "example.invalid", "server_port": 443},
        ], "authorization test")
        with self.assertRaisesRegex(ValueError, "授权"):
            manager.start_task({"import_id": imported["id"], "providers": ["ip_api"]})

    def test_history_limit_only_controls_index_and_does_not_delete_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, csv_dir, reports = root / "raw", root / "csv", root / "reports"
            raw.mkdir(); csv_dir.mkdir(); reports.mkdir()
            for index in range(3):
                run_id = f"20260808_12000{index}_abcde{index}"
                payload = {
                    "run_id": run_id, "source_label": "history", "kernel": "sing-box",
                    "status": "completed", "created_at": index + 1, "finished_at": index + 1,
                    "results": [],
                }
                (raw / f"run_{run_id}.json").write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(lib_tasks, "RESULT_RAW", raw), patch.object(lib_tasks, "RESULT_CSV", csv_dir), patch.object(lib_tasks, "RESULT_REPORT", reports):
                manager = TaskManager(history_limit=2)
                self.assertEqual(len(manager.list_tasks()), 2)
                manager.reload_history(1)
                self.assertEqual(len(manager.list_tasks()), 1)
            self.assertEqual(len(list(raw.glob("*.json"))), 3)


if __name__ == "__main__":
    unittest.main()
