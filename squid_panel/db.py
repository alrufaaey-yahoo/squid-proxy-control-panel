import os
import sqlite3
from flask import current_app, g


def database_path():
    return current_app.config.get("DATABASE") or os.environ.get("SQUID_PANEL_DB", "/var/lib/squid-panel/panel.sqlite3")


def get_db():
    if "db" not in g:
        db = sqlite3.connect(database_path(), timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 10000")
        g.db = db
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path=None):
    db = sqlite3.connect(path or database_path(), timeout=10)
    db.executescript("""
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS proxy_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login_name TEXT NOT NULL,
            remote_addr TEXT NOT NULL,
            succeeded INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup
            ON login_attempts(login_name, remote_addr, created_at);
    """)
    db.commit()
    db.close()


def audit(event, detail=""):
    db = get_db()
    db.execute("INSERT INTO audit_log(event, detail) VALUES (?, ?)", (event[:80], detail[:300]))
    db.commit()
