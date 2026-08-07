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


if __name__ == "__main__":
    unittest.main()
