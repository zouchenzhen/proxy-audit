import io
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from web_app import create_app


class WebApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = create_app(testing=True).test_client()

    def test_health_and_system(self):
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.get_json()["ok"])
        system = self.client.get("/api/system").get_json()
        self.assertEqual({item["id"] for item in system["kernels"]}, {"sing-box", "xray"})
        self.assertNotIn("ipqs_api_key", system["settings"])

    def test_online_ui_cors_is_limited_to_official_pages_origin(self):
        origin = "https://proxy-audit.pages.dev"
        preflight = self.client.options("/api/system", headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Private-Network": "true",
        })
        self.assertEqual(preflight.status_code, 204)
        self.assertEqual(preflight.headers["Access-Control-Allow-Origin"], origin)
        self.assertEqual(preflight.headers["Access-Control-Allow-Private-Network"], "true")
        allowed = self.client.get("/api/health", headers={"Origin": origin})
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.headers["Access-Control-Allow-Origin"], origin)
        denied = self.client.get("/api/health", headers={"Origin": "https://example.invalid"})
        self.assertEqual(denied.status_code, 403)
        self.assertNotIn("Access-Control-Allow-Origin", denied.headers)
        local_custom_port = self.client.post(
            "/api/import",
            headers={"Origin": "http://127.0.0.1:54321"},
            data={"source_type": "paste", "content": "socks://local-port.invalid:1080#CustomPort"},
        )
        self.assertEqual(local_custom_port.status_code, 200)

    def test_local_legal_page_and_authorization_gate(self):
        legal = self.client.get("/legal")
        self.assertEqual(legal.status_code, 200)
        self.assertIn("Proxy Audit · 使用与隐私说明", legal.get_data(as_text=True))
        self.assertIn("使用、隐私与安全边界", legal.get_data(as_text=True))
        legal.close()
        imported = self.client.post(
            "/api/import",
            data={"source_type": "paste", "content": "vless://00000000-0000-0000-0000-000000000009@example.invalid:443#Owned"},
        ).get_json()
        denied = self.client.post("/api/tasks", json={"import_id": imported["id"], "providers": ["ip_api"]})
        self.assertEqual(denied.status_code, 400)
        self.assertIn("授权", denied.get_json()["error"])

    def test_import_pasted_links_redacts_credentials(self):
        link = "vless://00000000-0000-0000-0000-000000000099@example.com:443?security=tls#WebTest"
        response = self.client.post("/api/import", data={"source_type":"paste", "content":link})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["total"], 1)
        serialized = str(payload)
        self.assertNotIn("00000000-0000-0000-0000-000000000099", serialized)
        self.assertEqual(payload["preview"][0]["remark"], "WebTest")
        restored = self.client.get(f"/api/imports/{payload['id']}")
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.get_json()["preview"][0]["remark"], "WebTest")
        self.assertNotIn("00000000-0000-0000-0000-000000000099", str(restored.get_json()))

    def test_import_text_file(self):
        data = {"source_type":"file", "file":(io.BytesIO(b"trojan://safe@example.com:443#Trojan"), "nodes.txt")}
        response = self.client.post("/api/import", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["protocols"]["trojan"], 1)

    def test_unknown_protocol_preview_redacts_userinfo(self):
        secret = "credential-must-not-leak"
        response = self.client.post("/api/import", data={"source_type":"paste", "content":f"socks://{secret}@example.invalid:1080#Safe"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(secret, str(response.get_json()))


if __name__ == "__main__":
    unittest.main()
