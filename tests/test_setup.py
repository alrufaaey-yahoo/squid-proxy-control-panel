import os
import sqlite3
import tempfile
import unittest
from squid_panel.db import init_db
from squid_panel.setup import persist_admin


class SetupResumeTests(unittest.TestCase):
    def test_admin_update_preserves_proxy_accounts_and_existing_policy(self):
        with tempfile.TemporaryDirectory() as tempdir:
            database = os.path.join(tempdir, "panel.sqlite3")
            init_db(database)
            db = sqlite3.connect(database)
            db.executemany("INSERT INTO settings(key,value) VALUES(?,?)", [
                ("proxy_port", "4555"),
                ("safe_ports", "80,443,8443"),
                ("allowed_clients", "203.0.113.8/32"),
            ])
            db.execute("INSERT INTO proxy_users(username,password_hash) VALUES(?,?)", ("alice", "$2y$12$" + "a" * 53))
            db.commit()
            db.close()

            persist_admin(database, "new-admin", "scrypt:test-hash", 8090)

            db = sqlite3.connect(database)
            settings = dict(db.execute("SELECT key,value FROM settings"))
            users = db.execute("SELECT username,password_hash FROM proxy_users").fetchall()
            db.close()
            self.assertEqual(settings["admin_username"], "new-admin")
            self.assertEqual(settings["admin_password_hash"], "scrypt:test-hash")
            self.assertEqual(settings["panel_port"], "8090")
            self.assertEqual(settings["proxy_port"], "4555")
            self.assertEqual(settings["safe_ports"], "80,443,8443")
            self.assertEqual(settings["allowed_clients"], "203.0.113.8/32")
            self.assertEqual(users, [("alice", "$2y$12$" + "a" * 53)])
            self.assertEqual(settings["ssl_ports"], "443")


if __name__ == "__main__":
    unittest.main()
