import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from lib_singbox import build_singbox_config, resolve_singbox_binary
from lib_v2rayn import describe_support, load_from_text, parse_share_link, row_to_node
from lib_xray import build_xray_config, describe_xray_support, resolve_xray_binary


class ShareLinkParserTests(unittest.TestCase):
    def test_vless_reality(self):
        node = parse_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality&pbk=public&sid=abcd&sni=www.example.com#JP")
        self.assertEqual(node["protocol"], "vless")
        self.assertEqual(node["tls_mode"], "reality")
        self.assertEqual(node["public_key"], "public")

    def test_vmess_base64_json(self):
        payload = {"v":"2","ps":"HK test","add":"example.com","port":"443","id":"00000000-0000-0000-0000-000000000002","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"cdn.example.com"}
        encoded = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        node = parse_share_link("vmess://" + encoded)
        self.assertEqual(node["remark"], "HK test")
        self.assertEqual(node["network"], "ws")
        self.assertEqual(node["server_port"], 443)

    def test_modern_protocols(self):
        hy2 = parse_share_link("hysteria2://safe-password@example.com:443?sni=h.example.com&obfs=salamander&obfs-password=mask#HY2")
        tuic = parse_share_link("tuic://00000000-0000-0000-0000-000000000003:safe-password@example.com:443?sni=t.example.com&congestion_control=bbr#TUIC")
        anytls = parse_share_link("anytls://safe-password@example.com:443?sni=a.example.com#AnyTLS")
        self.assertEqual(hy2["hy2_password"], "safe-password")
        self.assertEqual(tuic["tuic_password"], "safe-password")
        self.assertEqual(anytls["password"], "safe-password")

    def test_shadowsocks_sip002(self):
        credentials = base64.urlsafe_b64encode(b"aes-256-gcm:safe-password").decode().rstrip("=")
        node = parse_share_link(f"ss://{credentials}@example.com:8388#SS")
        self.assertEqual(node["security"], "aes-256-gcm")
        self.assertEqual(node["password"], "safe-password")

    def test_shadowsocks_plugin_is_explicitly_unsupported(self):
        credentials = base64.urlsafe_b64encode(b"aes-256-gcm:safe-password").decode().rstrip("=")
        node = parse_share_link(f"ss://{credentials}@example.com:8388#SS")
        node["tls_mode"] = "tls"
        supported, reason = describe_support(node)
        self.assertFalse(supported)
        self.assertIn("plugin", reason.lower())

    def test_base64_subscription_body(self):
        body = "vless://00000000-0000-0000-0000-000000000004@example.com:443?security=tls#One\n"
        encoded = base64.b64encode(body.encode()).decode()
        nodes = load_from_text(encoded)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["protocol"], "vless")

    def test_unknown_protocol_never_uses_raw_url_as_remark(self):
        secret = "credential-must-not-leak"
        node = parse_share_link(f"socks://{secret}@example.invalid:1080#SafeRemark")
        self.assertEqual(node["remark"], "SafeRemark")
        self.assertNotIn(secret, json.dumps(node))

    def test_current_v2rayn_database_schema_mapping(self):
        base = {
            "IndexId": "id", "Address": "example.com", "Port": 443, "Remarks": "DB node",
            "Subid": "", "IsSub": 0, "StreamSecurity": "tls", "AllowInsecure": "false",
            "Sni": "sni.example.com", "Alpn": "", "Fingerprint": "chrome",
            "PublicKey": "", "ShortId": "", "Extra": "", "Flow": "",
            "RequestHost": "", "Path": "", "HeaderType": "", "AlterId": 0,
            "Security": "", "Id": "", "Username": "", "Password": "",
            "ProtoExtra": "{}", "TransportExtra": "{}", "Network": "raw",
        }
        vmess = row_to_node({**base, "ConfigType": 1, "Password": "vmess-uuid", "ProtoExtra": '{"VmessSecurity":"auto"}'}, {}, "db", "test.db")
        self.assertEqual(vmess["uuid"], "vmess-uuid")
        self.assertEqual(vmess["network"], "tcp")
        self.assertEqual(vmess["security"], "auto")

        shadowsocks = row_to_node({**base, "ConfigType": 3, "StreamSecurity": "", "Password": "ss-password", "ProtoExtra": '{"SsMethod":"aes-256-gcm"}'}, {}, "db", "test.db")
        self.assertEqual(shadowsocks["protocol"], "ss")
        self.assertEqual(shadowsocks["password"], "ss-password")
        self.assertEqual(shadowsocks["security"], "aes-256-gcm")

        socks = row_to_node({**base, "ConfigType": 4, "Username": "socks-user", "Password": "socks-password"}, {}, "db", "test.db")
        self.assertEqual(socks["protocol"], "socks")

        tuic = row_to_node({**base, "ConfigType": 8, "Username": "tuic-uuid", "Password": "tuic-password", "ProtoExtra": '{"CongestionControl":"bbr"}'}, {}, "db", "test.db")
        self.assertEqual(tuic["uuid"], "tuic-uuid")
        self.assertEqual(tuic["tuic_password"], "tuic-password")
        self.assertEqual(tuic["congestion_control"], "bbr")
        self.assertEqual(tuic["tls_mode"], "tls")


class KernelConfigTests(unittest.TestCase):
    def setUp(self):
        self.node = parse_share_link("vless://00000000-0000-0000-0000-000000000005@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws&sni=cdn.example.com#Test")

    def test_singbox_config_has_local_socks(self):
        config = build_singbox_config(self.node, 23123)
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(config["inbounds"][0]["listen_port"], 23123)

    def test_xray_config(self):
        supported, reason = describe_xray_support(self.node)
        self.assertTrue(supported, reason)
        config = build_xray_config(self.node, 23124)
        self.assertEqual(config["inbounds"][0]["port"], 23124)
        self.assertEqual(config["outbounds"][0]["protocol"], "vless")
        self.assertNotIn("allowInsecure", config["outbounds"][0]["streamSettings"]["tlsSettings"])

    def test_tuic_alpn_is_nested_under_tls(self):
        node = parse_share_link("tuic://00000000-0000-0000-0000-000000000006:safe-password@example.com:443?sni=t.example.com&alpn=h3&congestion_control=bbr#TUIC")
        config = build_singbox_config(node, 23127)
        outbound = config["outbounds"][0]
        self.assertNotIn("alpn", outbound)
        self.assertEqual(outbound["tls"]["alpn"], ["h3"])

    def test_installed_kernels_accept_generated_configs(self):
        vmess_payload = {
            "v": "2", "ps": "VMess", "add": "example.com", "port": "443",
            "id": "00000000-0000-0000-0000-000000000007", "aid": "0", "scy": "auto",
            "net": "tcp", "tls": "", "sni": "example.com",
        }
        vmess = parse_share_link("vmess://" + base64.b64encode(json.dumps(vmess_payload).encode()).decode().rstrip("="))
        credentials = base64.urlsafe_b64encode(b"aes-256-gcm:safe-password").decode().rstrip("=")
        nodes = {
            "vless": self.node,
            "vmess": vmess,
            "trojan": parse_share_link("trojan://safe-password@example.com:443?security=tls&sni=example.com#Trojan"),
            "ss": parse_share_link(f"ss://{credentials}@example.com:8388#SS"),
            "hysteria2": parse_share_link("hysteria2://safe-password@example.com:443?sni=example.com#HY2"),
            "tuic": parse_share_link("tuic://00000000-0000-0000-0000-000000000008:safe-password@example.com:443?sni=example.com&alpn=h3&congestion_control=bbr#TUIC"),
            "anytls": parse_share_link("anytls://safe-password@example.com:443?sni=example.com#AnyTLS"),
        }
        checks = []
        for offset, (protocol, node) in enumerate(nodes.items()):
            checks.append((f"sing-box:{protocol}", resolve_singbox_binary(), build_singbox_config(node, 23200 + offset), lambda binary, path: [str(binary), "check", "-c", str(path)]))
        for offset, protocol in enumerate(("vless", "vmess", "trojan", "ss")):
            checks.append((f"xray:{protocol}", resolve_xray_binary(), build_xray_config(nodes[protocol], 23300 + offset), lambda binary, path: [str(binary), "run", "-test", "-c", str(path)]))

        for label, binary, config, command in checks:
            if not binary.exists():
                continue
            with self.subTest(pair=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "config.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                completed = subprocess.run(command(binary, path), capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
