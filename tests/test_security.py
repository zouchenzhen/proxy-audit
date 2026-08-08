import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lib_secrets
import lib_tasks
from lib_report import build_summary_rows
from lib_tasks import TaskManager


class SecureSettingsTests(unittest.TestCase):
    def test_save_load_and_clear_legacy_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secure = root / "config.secure.json"
            legacy = root / "config.local.json"
            legacy.write_text(json.dumps({"ipqs_api_key": "legacy-secret"}), encoding="utf-8")
            with patch.object(lib_secrets, "SECURE_CONFIG", secure), patch.object(lib_secrets, "LEGACY_CONFIG", legacy):
                lib_secrets.save_settings({"ipinfo_api_key": "new-secret"})
                loaded = lib_secrets.load_settings()
                self.assertEqual(loaded["ipinfo_api_key"], "new-secret")
                self.assertEqual(loaded["ipqs_api_key"], "legacy-secret")
                lib_secrets.save_settings({}, clear_fields=["ipqs_api_key"])
                self.assertEqual(lib_secrets.load_settings().get("ipqs_api_key"), "")
                wrapper = secure.read_text(encoding="utf-8")
                self.assertNotIn("new-secret", wrapper)

    def test_history_limit_is_bounded_and_public(self):
        with tempfile.TemporaryDirectory() as directory:
            secure = Path(directory) / "config.secure.json"
            legacy = Path(directory) / "config.local.json"
            with patch.object(lib_secrets, "SECURE_CONFIG", secure), patch.object(lib_secrets, "LEGACY_CONFIG", legacy):
                lib_secrets.save_settings({"history_limit": 37})
                self.assertEqual(lib_secrets.public_settings()["history_limit"], 37)


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
            self.assertIsNotNone(restored)
            self.assertEqual(restored["success"], 1)
            self.assertEqual(restored["rows"][0]["remark"], "safe")

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
