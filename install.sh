#!/usr/bin/env bash
# qWDTT HTTPS panel installer. Launch flags = packaging/wdtt.service
# (stock SpaceNeuroX unit + -web-port 46102 and TCP 46102).
#
#   curl -fsSL https://raw.githubusercontent.com/MaxPain99/qwdtt-panel/master/install.sh | sudo bash
set -euo pipefail

readonly SCRIPT_VERSION="2.0"
readonly REPO_URL="${QWDTT_REPO:-https://github.com/MaxPain99/qwdtt-panel.git}"
readonly REPO_BRANCH="${QWDTT_BRANCH:-master}"
readonly SRC_DIR="${QWDTT_SRC_DIR:-/opt/qwdtt-panel}"
readonly BIN_PATH="/usr/local/bin/wdtt-server"
readonly CONFIG_DIR="/etc/wdtt"
readonly LOG_FILE="/var/log/qwdtt-panel-install.log"
readonly CRED_FILE="${CONFIG_DIR}/credentials.txt"
readonly UNIT_PATH="/etc/systemd/system/wdtt.service"
readonly GO_VERSION="${QWDTT_GO_VERSION:-1.25.0}"

WEB_PORT="${QWDTT_WEB_PORT:-46102}"
WEB_USER="${QWDTT_WEB_USER:-admin}"
OWNER_PASS="${QWDTT_PASSWORD:-}"
WEB_PASS="${QWDTT_WEB_PASS:-}"

log_info()  { echo "[+] $*" | tee -a "$LOG_FILE"; }
log_warn()  { echo "[!] $*" | tee -a "$LOG_FILE"; }
log_error() { echo "[x] $*" | tee -a "$LOG_FILE"; }
die() { log_error "$*"; exit 1; }

need_root() {
    [ "$(id -u)" -eq 0 ] || die "Запустите от root"
}

rand_pass() {
    local n="${1:-16}" out=""
    if command -v openssl >/dev/null 2>&1; then
        out="$(openssl rand -base64 48 2>/dev/null | tr -d '\n/+=' | head -c "$n" || true)"
    fi
    if [ "${#out}" -lt "$n" ]; then
        out="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$n" || true)"
    fi
    [ "${#out}" -ge 8 ] || die "Не удалось сгенерировать пароль"
    printf '%s' "$out"
}

public_ip() {
    local ip=""
    ip="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    [ -n "$ip" ] || ip="$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
    [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    printf '%s' "${ip:-127.0.0.1}"
}

os_packages() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
    fi
    case "${ID:-}" in
        ubuntu|debian|linuxmint|pop)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y >>"$LOG_FILE" 2>&1 || true
            apt-get install -y -qq ca-certificates curl git openssl iproute2 iptables procps >>"$LOG_FILE" 2>&1 \
                || die "apt: не удалось поставить пакеты"
            ;;
        fedora)
            dnf install -y ca-certificates curl git openssl iproute iptables procps-ng >>"$LOG_FILE" 2>&1 \
                || die "dnf: не удалось поставить пакеты"
            ;;
        centos|rhel|rocky|almalinux|oracle)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y ca-certificates curl git openssl iproute iptables procps-ng >>"$LOG_FILE" 2>&1 \
                    || die "dnf: не удалось поставить пакеты"
            else
                yum install -y ca-certificates curl git openssl iproute iptables procps-ng >>"$LOG_FILE" 2>&1 \
                    || die "yum: не удалось поставить пакеты"
            fi
            ;;
        *)
            command -v curl >/dev/null 2>&1 || die "нужен curl"
            command -v git >/dev/null 2>&1 || die "нужен git"
            ;;
    esac
    command -v systemctl >/dev/null 2>&1 || die "нужен systemd"
}

go_ok() {
    command -v go >/dev/null 2>&1 || return 1
    local ver
    ver="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//' | awk -F. '{print $1"."$2}')"
    awk -v v="$ver" 'BEGIN { split(v, a, "."); exit !((a[1] > 1) || (a[1] == 1 && a[2] >= 21)) }'
}

install_go() {
    export PATH="/usr/local/go/bin:${PATH}"
    if go_ok; then
        log_info "Go: $(go version | awk '{print $3}')"
        return 0
    fi
    local arch goarch tarball
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) goarch="amd64" ;;
        aarch64|arm64) goarch="arm64" ;;
        *) die "архитектура $arch" ;;
    esac
    tarball="/tmp/go${GO_VERSION}.linux-${goarch}.tar.gz"
    curl -fL --retry 3 -o "$tarball" "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" \
        || die "не удалось скачать Go"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tarball"
    rm -f "$tarball"
    export PATH="/usr/local/go/bin:${PATH}"
    go_ok || die "Go не запустился"
    log_info "$(go version)"
}

fetch_sources() {
    if [ -d "${SRC_DIR}/.git" ]; then
        git -C "$SRC_DIR" remote set-url origin "$REPO_URL" >>"$LOG_FILE" 2>&1 || true
        git -C "$SRC_DIR" fetch --depth 1 origin "$REPO_BRANCH" >>"$LOG_FILE" 2>&1 || die "git fetch"
        git -C "$SRC_DIR" checkout -q FETCH_HEAD >>"$LOG_FILE" 2>&1 || die "git checkout"
    else
        rm -rf "$SRC_DIR"
        git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SRC_DIR" >>"$LOG_FILE" 2>&1 || die "git clone"
    fi
    [ -d "${SRC_DIR}/server" ] || die "нет ${SRC_DIR}/server"
}

build_server() {
    export PATH="/usr/local/go/bin:${PATH}"
    export CGO_ENABLED=0
    export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
    export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
    (
        cd "$SRC_DIR"
        go build -trimpath -ldflags '-s -w' -o /tmp/wdtt-server ./server
    ) >>"$LOG_FILE" 2>&1 || die "сборка не удалась, см. $LOG_FILE"
    install -m 0755 /tmp/wdtt-server "$BIN_PATH"
    rm -f /tmp/wdtt-server
    log_info "бинарник $BIN_PATH"
}

seed_secrets() {
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    if [ -z "$OWNER_PASS" ] && [ -s "${CONFIG_DIR}/main.password" ]; then
        OWNER_PASS="$(tr -d '\r\n' < "${CONFIG_DIR}/main.password")"
    fi
    if [ -z "$OWNER_PASS" ]; then
        OWNER_PASS="$(rand_pass 18)"
    fi
    printf '%s\n' "$OWNER_PASS" > "${CONFIG_DIR}/main.password"
    chmod 600 "${CONFIG_DIR}/main.password"

    if [ -z "$WEB_PASS" ] && [ -s "${CONFIG_DIR}/web.password" ]; then
        WEB_PASS="$(tr -d '\r\n' < "${CONFIG_DIR}/web.password")"
    fi
    if [ -z "$WEB_PASS" ]; then
        WEB_PASS="$(rand_pass 16)"
    fi
    printf '%s\n' "$WEB_PASS" > "${CONFIG_DIR}/web.password"
    chmod 600 "${CONFIG_DIR}/web.password"

    if [ ! -s "${CONFIG_DIR}/admin.token" ]; then
        rand_pass 32 > "${CONFIG_DIR}/admin.token"
        chmod 600 "${CONFIG_DIR}/admin.token"
    fi
    if [ ! -s "${CONFIG_DIR}/admin.crt" ] || [ ! -s "${CONFIG_DIR}/admin.key" ]; then
        openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
            -keyout "${CONFIG_DIR}/admin.key" \
            -out "${CONFIG_DIR}/admin.crt" \
            -subj "/CN=qwdtt-admin" >/dev/null 2>&1 || die "admin TLS"
        chmod 600 "${CONFIG_DIR}/admin.key" "${CONFIG_DIR}/admin.crt"
    fi

    cat > "$CRED_FILE" <<EOF
PANEL_URL=https://$(public_ip):${WEB_PORT}
WEB_USER=${WEB_USER}
WEB_PASS=${WEB_PASS}
OWNER_PASSWORD=${OWNER_PASS}
EOF
    chmod 600 "$CRED_FILE"
}

write_unit() {
    local src="${SRC_DIR}/packaging/wdtt.service"
    [ -f "$src" ] || die "нет $src"
    install -m 0644 "$src" "$UNIT_PATH"
    systemctl daemon-reload
    systemctl unmask wdtt >/dev/null 2>&1 || true
    systemctl enable wdtt >/dev/null 2>&1 || true
    log_info "unit: stock SpaceNeuroX + -web-port ${WEB_PORT}"
}

do_install() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== installer v${SCRIPT_VERSION} $(date -Iseconds) ===" >>"$LOG_FILE"
    echo "qWDTT panel installer v${SCRIPT_VERSION}"
    os_packages
    install_go
    fetch_sources
    build_server
    mkdir -p /usr/local/lib/qwdtt
    [ -f "${SRC_DIR}/server/update-server.sh" ] && install -m 0755 "${SRC_DIR}/server/update-server.sh" /usr/local/lib/qwdtt/update-server.sh
    seed_secrets
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    write_unit
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw allow 56000/udp >/dev/null 2>&1 || true
        ufw allow 56002/udp >/dev/null 2>&1 || true
        ufw allow 56003/udp >/dev/null 2>&1 || true
        ufw allow "${WEB_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    systemctl restart wdtt
    sleep 2
    if ! systemctl is-active --quiet wdtt; then
        log_error "сервис не запустился"
        journalctl -u wdtt -n 40 --no-pager | tee -a "$LOG_FILE" || true
        exit 1
    fi
    echo
    echo "Панель:   https://$(public_ip):${WEB_PORT}"
    echo "Логин:    ${WEB_USER}"
    echo "Пароль:   ${WEB_PASS}"
    echo "VPN pass: ${OWNER_PASS}"
    echo "Учётка:   ${CRED_FILE}"
}

do_update() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "qWDTT panel installer v${SCRIPT_VERSION}"
    export PATH="/usr/local/go/bin:${PATH}"
    install_go
    fetch_sources
    build_server
    mkdir -p /usr/local/lib/qwdtt
    [ -f "${SRC_DIR}/server/update-server.sh" ] && install -m 0755 "${SRC_DIR}/server/update-server.sh" /usr/local/lib/qwdtt/update-server.sh
    log_info "systemd unit не трогаю"
    systemctl restart wdtt
    log_info "обновлено"
}

main() {
    need_root
    case "${1:-install}" in
        install|--install|-i) do_install ;;
        update|--update) do_update ;;
        write-unit|--write-unit)
            [ -d "$SRC_DIR" ] || fetch_sources
            write_unit
            systemctl restart wdtt
            ;;
        *) die "команды: install | update | write-unit" ;;
    esac
}

main "$@"
