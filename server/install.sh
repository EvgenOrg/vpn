#!/usr/bin/env bash
#
# Security VPN: установка серверной части на чистый Ubuntu 24.04 / Debian 12.
#
#   sudo bash server/install.sh
#
# Что делает: ставит nginx + PHP + MariaDB + Xray, создаёт базу, включает VLESS+Reality на порту 443
# и HTTPS API на порту 8443 (самоподписанный сертификат, приложение сверяет его отпечаток).
# Скрипт можно запускать повторно: пароли, ключи и сертификат не пересоздаются.
#
# Необязательные переменные окружения:
#   SERVER_HOST=...   адрес сервера (по умолчанию определяется автоматически)
#   REALITY_SNI=...   сайт для маскировки Reality (по умолчанию www.microsoft.com)
#   API_PORT=8443     порт HTTPS API
#   XRAY_PORT=443     порт VPN

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Запустите от root:  sudo bash server/install.sh" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/opt/securityvpn
CONF_DIR=/etc/securityvpn
TLS_DIR="$CONF_DIR/tls"
API_PORT="${API_PORT:-8443}"
XRAY_PORT="${XRAY_PORT:-443}"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"
DB_NAME=security_vpn
DB_USER=svpn

say()  { printf '\n\033[1;35m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

. /etc/os-release
case "${ID:-}" in
    ubuntu|debian) ;;
    *) warn "Скрипт проверялся на Ubuntu 24.04 и Debian 12, у вас: ${PRETTY_NAME:-неизвестно}" ;;
esac

[[ -f "$REPO_DIR/api/schema.sql" ]] || die "Не нахожу api/schema.sql. Запускайте скрипт из склонированного репозитория."

# ---------------------------------------------------------------- пакеты
say "Устанавливаю пакеты (nginx, PHP, MariaDB)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y nginx mariadb-server php-fpm php-mysql php-cli openssl curl jq ca-certificates

systemctl enable --now mariadb

# ---------------------------------------------------------------- Xray
if [[ ! -x /usr/local/bin/xray ]]; then
    say "Устанавливаю Xray (официальный установщик XTLS/Xray-install)"
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
fi
[[ -x /usr/local/bin/xray ]] || die "Xray не установился. Проверьте, что сервер видит github.com."

# ---------------------------------------------------------------- адрес сервера и локация
install -d -m 755 "$CONF_DIR"
install -d -m 700 "$TLS_DIR"

if [[ -n "${SERVER_HOST:-}" ]]; then
    HOST="$SERVER_HOST"
elif [[ -f "$CONF_DIR/server.json" ]]; then
    HOST="$(jq -r .host "$CONF_DIR/server.json")"
else
    HOST="$(curl -fsS4 --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    [[ -n "$HOST" ]] || HOST="$(hostname -I | awk '{print $1}')"
fi
[[ -n "$HOST" ]] || die "Не удалось определить адрес сервера. Задайте его: SERVER_HOST=1.2.3.4 sudo -E bash server/install.sh"

# ---------------------------------------------------------------- ключи Reality и server.json
if [[ ! -f "$CONF_DIR/reality.json" ]]; then
    say "Генерирую ключи Reality"
    KEYS="$(/usr/local/bin/xray x25519)"
    # Версии Xray печатают по-разному: "Public key", "Password" или "Password (PublicKey)"; приватный ключ — всегда "Private key"/"PrivateKey"
    PRIV="$(awk -F': *' 'tolower($1) ~ /^private ?key$/ {print $2}' <<<"$KEYS" | tr -d '[:space:]')"
    PUB="$(awk -F': *' 'tolower($1) ~ /(public|password)/ {print $2}' <<<"$KEYS" | head -n1 | tr -d '[:space:]')"
    [[ -n "$PRIV" && -n "$PUB" ]] || die "Не смог разобрать вывод 'xray x25519':
$KEYS"
    SHORT_ID="$(openssl rand -hex 8)"
    PLACEHOLDER_UUID="$(/usr/local/bin/xray uuid)"

    umask 077
    jq -n --arg priv "$PRIV" --arg uuid "$PLACEHOLDER_UUID" \
        '{privateKey: $priv, placeholderUuid: $uuid}' > "$CONF_DIR/reality.json"
    umask 022

    LOC_JSON='null'
    INFO="$(curl -fsS --max-time 8 "https://ipinfo.io/$HOST/json" 2>/dev/null || true)"
    if [[ -n "$INFO" ]] && jq -e .country >/dev/null 2>&1 <<<"$INFO"; then
        LOC_JSON="$(jq -c '{countryCode: .country, city: (.city // ""),
            lat: ((.loc // "0,0") | split(",")[0] | tonumber),
            lon: ((.loc // "0,0") | split(",")[1] | tonumber)}' <<<"$INFO")"
    fi

    jq -n --arg host "$HOST" --argjson port "$XRAY_PORT" --arg sni "$REALITY_SNI" \
          --arg pub "$PUB" --arg sid "$SHORT_ID" --argjson loc "$LOC_JSON" \
        '{name: "Security VPN", host: $host, port: $port, sni: $sni, publicKey: $pub, shortId: $sid,
          flow: "xtls-rprx-vision", fingerprint: "chrome", location: $loc}' > "$CONF_DIR/server.json"
fi

# ---------------------------------------------------------------- база данных
if [[ ! -f "$CONF_DIR/api.json" ]]; then
    say "Создаю базу данных"
    DB_PASS="$(openssl rand -hex 24)"
    INVITE_CODE="$(openssl rand -hex 4)"
    mariadb <<SQL
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
CREATE USER IF NOT EXISTS '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
ALTER USER '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
GRANT SELECT, INSERT, UPDATE, DELETE ON $DB_NAME.* TO '$DB_USER'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON $DB_NAME.* TO '$DB_USER'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
    umask 077
    jq -n --arg name "$DB_NAME" --arg user "$DB_USER" --arg pass "$DB_PASS" --arg invite "$INVITE_CODE" \
        '{db_host: "127.0.0.1", db_port: 3306, db_name: $name, db_user: $user, db_pass: $pass, invite_code: $invite}' \
        > "$CONF_DIR/api.json"
    umask 022
fi
mariadb "$DB_NAME" < "$REPO_DIR/api/schema.sql"

# api.json и server.json читает PHP (www-data), reality.json — только root
chown root:www-data "$CONF_DIR/api.json" "$CONF_DIR/server.json"
chmod 640 "$CONF_DIR/api.json" "$CONF_DIR/server.json"
chown root:root "$CONF_DIR/reality.json"
chmod 600 "$CONF_DIR/reality.json"

# ---------------------------------------------------------------- TLS-сертификат для API
if [[ ! -f "$TLS_DIR/cert.pem" ]]; then
    say "Создаю самоподписанный сертификат для API"
    if [[ "$HOST" =~ ^[0-9.]+$ ]]; then SAN="IP:$HOST"; else SAN="DNS:$HOST"; fi
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
        -subj "/CN=$HOST" -addext "subjectAltName=$SAN" 2>/dev/null
    chmod 600 "$TLS_DIR/key.pem"
fi
FINGERPRINT="$(openssl x509 -noout -fingerprint -sha256 -in "$TLS_DIR/cert.pem" | cut -d= -f2)"

# ---------------------------------------------------------------- файлы приложения
say "Копирую API в $APP_DIR"
install -d -m 755 "$APP_DIR"
rm -rf "$APP_DIR/api"
cp -a "$REPO_DIR/api" "$APP_DIR/api"
install -m 755 "$REPO_DIR/server/sync-xray.php" "$APP_DIR/sync-xray.php"
chown -R root:root "$APP_DIR"
chmod -R a+rX "$APP_DIR"

# ---------------------------------------------------------------- nginx
PHP_SOCK="$(ls /run/php/php*-fpm.sock 2>/dev/null | head -n1 || true)"
[[ -n "$PHP_SOCK" ]] || die "Не нашёл сокет php-fpm в /run/php/"
systemctl enable --now "$(basename "$PHP_SOCK" .sock)" 2>/dev/null || true

say "Настраиваю nginx (порт $API_PORT)"
sed -e "s|__API_PORT__|$API_PORT|g" -e "s|__APP_DIR__|$APP_DIR|g" -e "s|__PHP_SOCK__|$PHP_SOCK|g" \
    "$REPO_DIR/server/nginx.conf.tpl" > /etc/nginx/conf.d/securityvpn.conf
nginx -t
systemctl enable --now nginx
systemctl reload nginx

# ---------------------------------------------------------------- синхронизация пользователей и запуск Xray
say "Запускаю синхронизацию пользователей и Xray"
install -m 644 "$REPO_DIR/server/securityvpn-sync.service" /etc/systemd/system/securityvpn-sync.service
install -m 644 "$REPO_DIR/server/securityvpn-sync.timer"   /etc/systemd/system/securityvpn-sync.timer
systemctl daemon-reload
php "$APP_DIR/sync-xray.php"
systemctl enable --now securityvpn-sync.timer

# ---------------------------------------------------------------- фаервол (только если уже включён)
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    say "ufw активен, открываю порты $XRAY_PORT и $API_PORT"
    ufw allow "$XRAY_PORT"/tcp
    ufw allow "$API_PORT"/tcp
fi

# ---------------------------------------------------------------- проверка
say "Проверка"
sleep 2
systemctl is-active --quiet xray && echo "  Xray:   работает" || warn "Xray не запущен (journalctl -u xray -n 30)"
systemctl is-active --quiet nginx && echo "  nginx:  работает" || warn "nginx не запущен"
if API_REPLY="$(curl -fsSk --max-time 8 "https://127.0.0.1:$API_PORT/api/info" 2>/dev/null)"; then
    echo "  API:    отвечает  $API_REPLY"
else
    warn "API не отвечает (tail /var/log/nginx/error.log)"
fi
ss -ltn "( sport = :$XRAY_PORT )" | grep -q LISTEN && echo "  Порт $XRAY_PORT: слушает" || warn "Порт $XRAY_PORT никто не слушает"

INVITE="$(jq -r '.invite_code // ""' "$CONF_DIR/api.json")"

cat <<EOF

────────────────────────────────────────────────────────────
  Готово. Данные для приложения (app/config.json):

  {
    "apiUrl": "https://$HOST:$API_PORT",
    "certSha256": "$FINGERPRINT"
  }

  Код приглашения для регистрации: ${INVITE:-(не задан, регистрация открыта для всех)}
  (хранится в $CONF_DIR/api.json, поле invite_code; пустая строка = открытая регистрация)

  Если на хостинге (Aeza) есть внешний фаервол — откройте порты $XRAY_PORT/tcp и $API_PORT/tcp.
────────────────────────────────────────────────────────────
EOF
