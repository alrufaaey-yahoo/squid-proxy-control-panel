import os
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from squid_panel import create_app
from squid_panel.db import init_db
from squid_panel.security import parse_ports, valid_username, validate_domains, validate_networks, validate_password


class ValidationTests(unittest.TestCase):
    def test_username_policy(self):
        self.assertTrue(valid_username("proxy.user-1"))
        self.assertFalse(valid_username("../root"))
        self.assertFalse(valid_username("user name"))
        self.assertFalse(valid_username("-option"))

    def test_port_lists_are_normalized_and_bounded(self):
        self.assertEqual(parse_ports("443,80,443", "ports", "80"), "80,443")
        with self.assertRaises(ValueError):
            parse_ports("80;id", "ports", "80")
        with self.assertRaises(ValueError):
            parse_ports("65536", "ports", "80")

    def test_domain_and_network_validation(self):
        self.assertEqual(validate_domains("Example.COM\n.example.org\n"), ".example.org\nexample.com")
        with self.assertRaises(ValueError):
            validate_domains("bad..example")
        self.assertEqual(validate_networks("192.0.2.17/24\n"), "192.0.2.0/24")
        with self.assertRaises(ValueError):
            validate_networks("not-an-ip")

    def test_password_minimum(self):
        validate_password("a-long-test-password")
        with self.assertRaises(ValueError):
            validate_password("short")
        with self.assertRaises(ValueError):
            validate_password("x" * 73)
        with self.assertRaises(ValueError):
            validate_password("😀" * 19)


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "panel.sqlite3")
        init_db(self.db_path)
        db = sqlite3.connect(self.db_path)
        db.executemany("INSERT INTO settings(key,value) VALUES(?,?)", [
            ("admin_username", "admin"),
            ("admin_password_hash", generate_password_hash("correct-password-123")),
            ("panel_port", "8081"),
        ])
        db.commit()
        db.close()
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret-key", "DATABASE": self.db_path, "PANEL_PORT": 8081})
        self.client = self.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def csrf(self):
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        return re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()

    def sign_in(self):
        token = self.csrf()
        response = self.client.post("/login", data={"csrf_token": token, "username": "admin", "password": "correct-password-123"})
        self.assertEqual(response.status_code, 302)

    def test_authentication_and_csrf(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        token = self.csrf()
        rejected = self.client.post("/login", data={"csrf_token": "wrong", "username": "admin", "password": "correct-password-123"})
        self.assertEqual(rejected.status_code, 400)
        accepted = self.client.post("/login", data={"csrf_token": token, "username": "admin", "password": "correct-password-123"})
        self.assertEqual(accepted.status_code, 302)

    def test_export_omits_hashes(self):
        self.sign_in()
        response = self.client.get("/export")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"admin_password_hash", response.data)
        self.assertNotIn(b"password_hash", response.data)
        self.assertNotIn(b"admin_username", response.data)

    @patch("squid_panel.helper", side_effect=[(0, "Active: active (running)"), (0, "access log line")])
    def test_dashboard_renders_after_login(self, _mock_helper):
        self.sign_in()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("إدارة Squid Proxy".encode(), response.data)
        self.assertIn(b"access log line", response.data)

    @patch("squid_panel.helper", return_value=(0, "ok"))
    def test_settings_reject_same_panel_port(self, mock_helper):
        self.sign_in()
        with self.client.session_transaction() as sess:
            csrf = "csrf-for-test"
            sess["csrf"] = csrf
        response = self.client.post("/settings", data={"csrf_token": csrf, "proxy_port": "8081", "safe_ports": "80,443", "ssl_ports": "443"})
        self.assertEqual(response.status_code, 302)
        mock_helper.assert_not_called()
        conn = sqlite3.connect(self.db_path)
        value = conn.execute("SELECT value FROM settings WHERE key='proxy_port'").fetchone()
        conn.close()
        self.assertIsNone(value)


if __name__ == "__main__":
    unittest.main()
