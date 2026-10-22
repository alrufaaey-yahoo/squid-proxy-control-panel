import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from .db import audit, close_db, get_db, init_db
from .security import helper, make_squid_password_hash, parse_ports, valid_username, validate_domains, validate_networks

DEFAULTS = {
    "proxy_port": "3128",
    "safe_ports": "80,443",
    "ssl_ports": "443",
    "allowed_domains": "",
    "allowed_clients": "",
}


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SQUID_PANEL_SECRET", ""),
        DATABASE=os.environ.get("SQUID_PANEL_DB", "/var/lib/squid-panel/panel.sqlite3"),
        PANEL_PORT=int(os.environ.get("PANEL_PORT", "8080")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get("PANEL_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"},
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        if not app.testing:
            raise RuntimeError("SQUID_PANEL_SECRET must be configured before production startup")
        app.config["SECRET_KEY"] = secrets.token_urlsafe(48)
    app.teardown_appcontext(close_db)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        response.headers["Cache-Control"] = "no-store"
        return response

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    @app.context_processor
    def inject_csrf():
        return {"csrf_token": csrf_token}

    @app.before_request
    def enforce_csrf():
        if request.method == "POST":
            expected = session.get("csrf", "")
            supplied = request.form.get("csrf_token", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                abort(400, "رمز حماية الطلب غير صالح؛ أعد تحميل الصفحة وحاول مجددًا.")

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("admin"):
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapped

    def get_settings():
        rows = get_db().execute("SELECT key, value FROM settings").fetchall()
        result = dict(DEFAULTS)
        result.update({row["key"]: row["value"] for row in rows})
        return result

    def set_settings(values):
        db = get_db()
        db.executemany("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       list(values.items()))
        db.commit()

    def count_recent_failures(login_name, remote_addr):
        since = (datetime.now(timezone.utc) - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
        row = get_db().execute("SELECT COUNT(*) AS n FROM login_attempts WHERE login_name=? AND remote_addr=? AND succeeded=0 AND created_at >= ?",
                               (login_name[:80], remote_addr[:80], since)).fetchone()
        return row["n"]

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("admin"):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            remote = request.remote_addr or "unknown"
            db = get_db()
            row = db.execute("SELECT value FROM settings WHERE key='admin_username'").fetchone()
            stored_user = row["value"] if row else ""
            hash_row = db.execute("SELECT value FROM settings WHERE key='admin_password_hash'").fetchone()
            blocked = count_recent_failures(username, remote) >= 8
            ok = bool(not blocked and row and hash_row and username == stored_user and check_password_hash(hash_row["value"], password))
            db.execute("INSERT INTO login_attempts(login_name, remote_addr, succeeded) VALUES (?, ?, ?)", (username[:80], remote[:80], int(ok)))
            db.execute("DELETE FROM login_attempts WHERE created_at < datetime('now', '-2 days')")
            db.commit()
            if ok:
                session.clear()
                session["admin"] = stored_user
                session.permanent = True
                audit("admin_login", f"source={remote}")
                target = request.args.get("next", "")
                if target.startswith("/") and not target.startswith("//"):
                    return redirect(target)
                return redirect(url_for("dashboard"))
            flash("بيانات الدخول غير صحيحة أو تم تجاوز عدد المحاولات. حاول لاحقًا.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        audit("admin_logout", session.get("admin", ""))
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard():
        settings = get_settings()
        users = get_db().execute("SELECT username, created_at FROM proxy_users ORDER BY username COLLATE NOCASE").fetchall()
        audits = get_db().execute("SELECT event, detail, created_at FROM audit_log ORDER BY id DESC LIMIT 25").fetchall()
        status_code, status_text = helper("status", timeout=10)
        logs_code, logs_text = helper("logs", timeout=10)
        service_status = "نشط" if status_code == 0 and "active" in status_text.lower() else "غير نشط"
        logs = logs_text.splitlines()[-35:] if logs_code == 0 else ["تعذرت قراءة سجل Squid."]
        return render_template("dashboard.html", settings=settings, users=users, audits=audits,
                               service_status=service_status, service_detail=status_text, logs=logs)

    @app.post("/settings")
    @login_required
    def update_settings():
        try:
            port_text = request.form.get("proxy_port", "").strip()
            if not port_text.isdigit() or not 1024 <= int(port_text) <= 65535:
                raise ValueError("منفذ Squid يجب أن يكون بين 1024 و65535.")
            port = int(port_text)
            if port == int(app.config["PANEL_PORT"]):
                raise ValueError("يجب أن يختلف منفذ Squid عن منفذ لوحة التحكم.")
            values = {
                "proxy_port": str(port),
                "safe_ports": parse_ports(request.form.get("safe_ports", ""), "منافذ الوجهة المسموحة", "80,443"),
                "ssl_ports": parse_ports(request.form.get("ssl_ports", ""), "منافذ CONNECT", "443"),
                "allowed_domains": validate_domains(request.form.get("allowed_domains", "")),
                "allowed_clients": validate_networks(request.form.get("allowed_clients", "")),
            }
            if not set(values["ssl_ports"].split(",")).issubset(set(values["safe_ports"].split(","))):
                raise ValueError("يجب أن تكون منافذ CONNECT ضمن منافذ الوجهة المسموحة.")
            set_settings(values)
            code, output = helper("apply", timeout=45)
            if code:
                audit("settings_apply_failed", f"proxy_port={port}")
                flash("حُفظت الإعدادات لكن تعذّر تطبيقها؛ راجع سجلات النظام. " + output[:300], "error")
            else:
                audit("settings_updated", f"proxy_port={port}")
                flash("تم حفظ إعدادات Squid وتطبيقها بنجاح.", "success")
        except (ValueError, RuntimeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    @app.post("/users/add")
    @login_required
    def add_user():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            if not valid_username(username):
                raise ValueError("اسم المستخدم يجب أن يحتوي أحرفًا لاتينية أو أرقامًا أو . _ - وبحد أقصى 32 محرفًا.")
            password_hash = make_squid_password_hash(username, password)
            db = get_db()
            db.execute("INSERT INTO proxy_users(username, password_hash) VALUES (?, ?)", (username, password_hash))
            db.commit()
            code, output = helper("apply", timeout=45)
            if code:
                audit("proxy_user_apply_failed", username)
                flash("أُضيف المستخدم لكن تعذّر تطبيقه على Squid: " + output[:250], "error")
            else:
                audit("proxy_user_added", username)
                flash(f"تمت إضافة المستخدم {username} وتطبيقه.", "success")
        except sqlite3.IntegrityError:
            flash("اسم المستخدم مستخدم بالفعل.", "error")
        except (ValueError, RuntimeError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    @app.post("/users/<username>/password")
    @login_required
    def change_user_password(username):
        password = request.form.get("password", "")
        try:
            if not valid_username(username):
                abort(404)
            password_hash = make_squid_password_hash(username, password)
            db = get_db()
            cursor = db.execute("UPDATE proxy_users SET password_hash=? WHERE username=?", (password_hash, username))
            db.commit()
            if cursor.rowcount == 0:
                abort(404)
            code, output = helper("apply", timeout=45)
            if code:
                audit("proxy_password_apply_failed", username)
                flash("تم تحديث كلمة المرور لكن تعذّر تطبيق التغيير: " + output[:250], "error")
            else:
                audit("proxy_user_password_changed", username)
                flash(f"تم تغيير كلمة مرور {username}.", "success")
        except (ValueError, RuntimeError, OSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    @app.post("/users/<username>/delete")
    @login_required
    def delete_user(username):
        if not valid_username(username):
            abort(404)
        db = get_db()
        cursor = db.execute("DELETE FROM proxy_users WHERE username=?", (username,))
        db.commit()
        if cursor.rowcount:
            code, output = helper("apply", timeout=45)
            if code:
                audit("proxy_user_delete_apply_failed", username)
                flash("حُذف المستخدم من اللوحة لكن تعذّر تطبيق التغيير: " + output[:250], "error")
            else:
                audit("proxy_user_deleted", username)
                flash(f"تم حذف المستخدم {username}.", "success")
        else:
            flash("المستخدم غير موجود.", "error")
        return redirect(url_for("dashboard"))

    @app.post("/service/restart")
    @login_required
    def restart_service():
        code, output = helper("restart", timeout=45)
        if code == 0:
            audit("squid_restarted", session.get("admin", ""))
            flash("أُعيد تشغيل خدمة Squid.", "success")
        else:
            flash("تعذر إعادة التشغيل: " + output[:400], "error")
        return redirect(url_for("dashboard"))

    @app.get("/export")
    @login_required
    def export_config():
        settings = {key: value for key, value in get_settings().items() if key in DEFAULTS}
        users = [dict(row) for row in get_db().execute("SELECT username, created_at FROM proxy_users ORDER BY username")]
        response = jsonify({"format": "squid-proxy-panel-export-v1", "settings": settings, "proxy_users": users,
                            "note": "لا يحتوي هذا التصدير كلمات المرور أو تجزئاتها."})
        response.headers["Content-Disposition"] = "attachment; filename=squid-panel-config.json"
        return response

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=getattr(error, "description", "طلب غير صالح.")), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="الصفحة غير موجودة."), 404

    return app
