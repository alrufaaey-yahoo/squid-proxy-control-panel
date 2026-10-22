import importlib.machinery
import importlib.util
import pathlib
import unittest

HELPER_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "squid-panel-helper"
loader = importlib.machinery.SourceFileLoader("squid_panel_root_helper", str(HELPER_PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
root_helper = importlib.util.module_from_spec(spec)
loader.exec_module(root_helper)


class SquidConfigTests(unittest.TestCase):
    def test_empty_install_is_deny_all(self):
        config, passwd = root_helper.render({"proxy_port": "3128", "panel_port": "8080"}, [])
        self.assertIn("http_port 0.0.0.0:3128", config)
        self.assertIn("http_access deny all", config)
        self.assertNotIn("auth_param basic", config)
        self.assertEqual(passwd, "")

    def test_users_are_authenticated_and_network_restricted(self):
        root_helper.HELPER = str(HELPER_PATH)
        password_hash = "$2y$05$" + "a" * 53
        settings = {
            "proxy_port": "4400", "panel_port": "8080", "safe_ports": "80,443,8080",
            "ssl_ports": "443", "allowed_domains": "example.com\n.example.org",
            "allowed_clients": "203.0.113.9/32",
        }
        config, passwd = root_helper.render(settings, [{"username": "alice", "password_hash": password_hash}])
        self.assertIn("http_port 0.0.0.0:4400", config)
        self.assertIn("acl authenticated proxy_auth REQUIRED", config)
        self.assertIn("acl trusted_clients src 203.0.113.9/32", config)
        self.assertIn("acl allowed_domains dstdomain .example.org example.com", config)
        self.assertIn("http_access deny to_private_network", config)
        self.assertIn("http_access allow authenticated trusted_clients allowed_domains", config)
        self.assertEqual(passwd, f"alice:{password_hash}\n")
        self.assertLess(config.index("http_access deny to_private_network"), config.index("http_access allow authenticated"))

    def test_conflicting_listener_ports_rejected(self):
        with self.assertRaises(RuntimeError):
            root_helper.render({"proxy_port": "8080", "panel_port": "8080"}, [])

    def test_invalid_database_user_hash_rejected(self):
        with self.assertRaises(RuntimeError):
            root_helper.render({"proxy_port": "3128", "panel_port": "8080"}, [{"username": "bob", "password_hash": "plain-text"}])

    def test_config_injection_through_domain_rejected(self):
        with self.assertRaises(RuntimeError):
            root_helper.render({"proxy_port": "3128", "panel_port": "8080", "allowed_domains": "good.example\nhttp_access allow all"}, [])


if __name__ == "__main__":
    unittest.main()
