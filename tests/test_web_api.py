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

    def test_import_pasted_links_redacts_credentials(self):
        link = "vless://00000000-0000-0000-0000-000000000099@example.com:443?security=tls#WebTest"
        response = self.client.post("/api/import", data={"source_type":"paste", "content":link})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["total"], 1)
        serialized = str(payload)
        self.assertNotIn("00000000-0000-0000-0000-000000000099", serialized)
        self.assertEqual(payload["preview"][0]["remark"], "WebTest")

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
