import ipaddress
import re
import subprocess

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
DOMAIN_RE = re.compile(r"^\.?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^[A-Za-z0-9]$")


def valid_username(value):
    return bool(USERNAME_RE.fullmatch(value or "")) and value not in {".", ".."}


def validate_password(value):
    if not isinstance(value, str) or len(value) < 12 or len(value.encode("utf-8")) > 72:
        raise ValueError("يجب أن تكون كلمة المرور 12 محرفًا على الأقل وألا تتجاوز 72 بايتًا بصيغة UTF-8.")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("كلمة المرور تحتوي محارف غير مسموحة.")


def parse_ports(value, label, default):
    value = (value or "").strip()
    if not value:
        value = default
    parts = [p.strip() for p in value.split(",")]
    if not parts or any(not p.isdigit() for p in parts):
        raise ValueError(f"{label}: أدخل أرقام منافذ مفصولة بفواصل.")
    ports = sorted(set(int(p) for p in parts))
    if any(p < 1 or p > 65535 for p in ports):
        raise ValueError(f"{label}: يجب أن تكون المنافذ بين 1 و65535.")
    return ",".join(str(p) for p in ports)


def validate_domains(value):
    result = []
    for raw in (value or "").splitlines():
        domain = raw.strip().lower()
        if not domain or domain.startswith("#"):
            continue
        if not DOMAIN_RE.fullmatch(domain) or ".." in domain or "*" in domain:
            raise ValueError(f"اسم نطاق غير صالح: {domain[:80]}")
        result.append(domain)
    return "\n".join(sorted(set(result)))


def validate_networks(value):
    networks = []
    for raw in (value or "").splitlines():
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        try:
            networks.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError as exc:
            raise ValueError(f"نطاق IP/CIDR غير صالح: {item[:80]}") from exc
    return "\n".join(sorted(set(networks)))


def make_squid_password_hash(username, password):
    validate_password(password)
    if not valid_username(username):
        raise ValueError("اسم المستخدم غير صالح.")
    # Password is sent over stdin, never exposed in argv or shell history.
    proc = subprocess.run(
        ["/usr/bin/htpasswd", "-nB", "-C", "12", "-i", username],
        input=password + "\n", text=True, capture_output=True, timeout=10, check=False,
    )
    if proc.returncode != 0 or ":" not in proc.stdout:
        raise RuntimeError("تعذر إنشاء تجزئة كلمة مرور Squid باستخدام htpasswd.")
    return proc.stdout.strip().split(":", 1)[1]


def helper(action, timeout=30):
    if action not in {"status", "logs", "apply", "restart"}:
        raise ValueError("عملية نظام غير مسموحة.")
    proc = subprocess.run(
        ["/usr/bin/sudo", "-n", "/usr/local/sbin/squid-panel-helper", action],
        text=True, capture_output=True, timeout=timeout, check=False,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()[:12000]
