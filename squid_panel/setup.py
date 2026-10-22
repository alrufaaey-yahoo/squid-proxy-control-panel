import argparse
import getpass
import os
import sqlite3
import sys
from werkzeug.security import generate_password_hash
from .db import init_db

DEFAULT_SETTINGS = {
    "proxy_port": "3128",
    "safe_ports": "80,443",
    "ssl_ports": "443",
    "allowed_domains": "",
    "allowed_clients": "",
}


def persist_admin(database, username, password_hash, panel_port):
    """Create/update panel credentials while preserving proxy users and policy."""
    db = sqlite3.connect(database)
    admin_values = {
        "admin_username": username,
        "admin_password_hash": password_hash,
        "panel_port": str(panel_port),
    }
    db.executemany(
        "INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        admin_values.items(),
    )
    db.executemany(
        "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",
        DEFAULT_SETTINGS.items(),
    )
    db.commit()
    db.close()


def main():
    parser = argparse.ArgumentParser(description="Initialize or update the Squid Proxy Panel administrator")
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--panel-port", type=int, required=True)
    parser.add_argument("--database", default=os.environ.get("SQUID_PANEL_DB", "/var/lib/squid-panel/panel.sqlite3"))
    args = parser.parse_args()
    if not (1024 <= args.panel_port <= 65535):
        parser.error("panel port must be between 1024 and 65535")
    if not args.admin_user or len(args.admin_user) > 64 or any(c.isspace() for c in args.admin_user):
        parser.error("admin username must be 1-64 non-space characters")
    os.makedirs(os.path.dirname(args.database), mode=0o750, exist_ok=True)
    init_db(args.database)
    password = getpass.getpass("كلمة مرور مدير اللوحة (12 محرفًا على الأقل): ")
    confirm = getpass.getpass("أعد كتابة كلمة المرور: ")
    if len(password) < 12 or len(password) > 128 or password != confirm:
        print("كلمة المرور غير مطابقة أو أقصر من 12 محرفًا.", file=sys.stderr)
        return 2
    persist_admin(args.database, args.admin_user, generate_password_hash(password), args.panel_port)
    print("تم حفظ حساب مدير اللوحة مع الإبقاء على مستخدمي وإعدادات Squid الحالية.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
