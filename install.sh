#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/squid-proxy-panel"
DATA_DIR="/var/lib/squid-panel"
ETC_DIR="/etc/squid-panel"
SERVICE_USER="squid-panel"
SOURCE_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

fail() { echo "[خطأ] $*" >&2; exit 1; }
info() { echo "[Squid Panel] $*"; }

[[ "${EUID}" -eq 0 ]] || fail "شغّل المثبت بصلاحيات root: sudo bash install.sh"
[[ -f "$SOURCE_DIR/squid_panel/__init__.py" ]] || fail "شغّل المثبت من مجلد المستودع الكامل."
command -v apt-get >/dev/null || fail "يدعم المثبت Ubuntu وDebian اللذين يستخدمان apt فقط."
command -v systemctl >/dev/null || fail "يتطلب المثبت systemd."
[[ ! -e "$DATA_DIR/panel.sqlite3" ]] || fail "يوجد تثبيت سابق. استخدم دليل الترقية قبل إعادة التثبيت؛ لن يتم استبدال بياناتك."

read -r -p "منفذ لوحة التحكم (1024-65535، الافتراضي 8080): " PANEL_PORT
PANEL_PORT="${PANEL_PORT:-8080}"
[[ "$PANEL_PORT" =~ ^[0-9]+$ ]] && (( PANEL_PORT >= 1024 && PANEL_PORT <= 65535 )) || fail "منفذ اللوحة غير صالح."
[[ "$PANEL_PORT" != "3128" ]] || fail "اختر منفذًا غير 3128، وهو منفذ Squid الافتراضي."
read -r -p "اسم مستخدم مدير اللوحة: " ADMIN_USER
[[ -n "$ADMIN_USER" && ${#ADMIN_USER} -le 64 && "$ADMIN_USER" != *[[:space:]]* ]] || fail "اسم المستخدم يجب أن يكون 1-64 محرفًا بلا مسافات."

info "تثبيت الحزم المطلوبة..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y squid apache2-utils python3 python3-venv sudo ca-certificates openssl
systemctl stop squid || true

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR"
install -d -o root -g "$SERVICE_USER" -m 0750 "$ETC_DIR"
install -d -o root -g root -m 0755 "$APP_DIR"
if [[ "$SOURCE_DIR" != "$APP_DIR" ]]; then
  cp -a "$SOURCE_DIR/." "$APP_DIR/"
fi
chown -R root:root "$APP_DIR"
chmod 0755 "$APP_DIR/install.sh"

info "إنشاء بيئة Python الافتراضية وتثبيت التطبيق..."
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --disable-pip-version-check --upgrade pip
"$APP_DIR/.venv/bin/pip" install --disable-pip-version-check -r "$APP_DIR/requirements.txt"

install -o root -g root -m 0755 "$APP_DIR/scripts/squid-panel-helper" /usr/local/sbin/squid-panel-helper
cat > /etc/sudoers.d/squid-panel <<'SUDOERS'
squid-panel ALL=(root) NOPASSWD: /usr/local/sbin/squid-panel-helper status, /usr/local/sbin/squid-panel-helper logs, /usr/local/sbin/squid-panel-helper apply, /usr/local/sbin/squid-panel-helper restart
SUDOERS
chmod 0440 /etc/sudoers.d/squid-panel
visudo -cf /etc/sudoers.d/squid-panel >/dev/null || fail "ملف sudoers غير صالح."

PANEL_SECRET="$(/usr/bin/openssl rand -hex 48)"
cat > "$ETC_DIR/panel.env" <<EOF
PANEL_PORT=$PANEL_PORT
SQUID_PANEL_SECRET=$PANEL_SECRET
SQUID_PANEL_DB=$DATA_DIR/panel.sqlite3
PANEL_COOKIE_SECURE=false
EOF
chown root:"$SERVICE_USER" "$ETC_DIR/panel.env"
chmod 0640 "$ETC_DIR/panel.env"

info "تهيئة مدير اللوحة. لن تظهر كلمة المرور أثناء كتابتها."
cd "$APP_DIR"
sudo -u "$SERVICE_USER" env SQUID_PANEL_DB="$DATA_DIR/panel.sqlite3" "$APP_DIR/.venv/bin/python" -m squid_panel.setup --admin-user "$ADMIN_USER" --panel-port "$PANEL_PORT" --database "$DATA_DIR/panel.sqlite3"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR"
chmod 0640 "$DATA_DIR/panel.sqlite3"

cat > /etc/systemd/system/squid-panel.service <<'UNIT'
[Unit]
Description=Squid Proxy Management Panel
After=network-online.target squid.service
Wants=network-online.target

[Service]
Type=simple
User=squid-panel
Group=squid-panel
WorkingDirectory=/opt/squid-proxy-panel
EnvironmentFile=/etc/squid-panel/panel.env
ExecStart=/opt/squid-proxy-panel/.venv/bin/gunicorn --workers 2 --bind 0.0.0.0:${PANEL_PORT} --access-logfile - --error-logfile - squid_panel:create_app()
Restart=on-failure
RestartSec=3
TimeoutStopSec=20
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/squid-panel /etc/squid /var/log/squid /var/spool/squid
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
# Apply a deny-all Squid configuration first. The proxy stays closed until a
# user is created in the authenticated dashboard.
/usr/local/sbin/squid-panel-helper apply || fail "تعذر إعداد Squid في وضع الإغلاق الآمن؛ تحقق من سجلات التثبيت."
systemctl enable --now squid
systemctl enable --now squid-panel

PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
info "تم التثبيت بنجاح."
echo "لوحة التحكم: http://${PUBLIC_IP:-SERVER_IP}:${PANEL_PORT}"
echo "اسم المستخدم: ${ADMIN_USER}"
echo "أضف مستخدم Squid من اللوحة؛ حتى ذلك الحين يرفض البروكسي جميع الاتصالات."
echo "مهم: اضبط جدار VPS/UFW لفتح منفذ اللوحة ${PANEL_PORT} ومنفذ Squid الذي تختاره فقط لعناوينك الموثوقة."
echo "لإنتاج آمن، ضع اللوحة خلف HTTPS واضبط PANEL_COOKIE_SECURE=true في ${ETC_DIR}/panel.env ثم أعد تشغيل squid-panel."
