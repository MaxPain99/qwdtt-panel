#!/usr/bin/env bash
# qWDTT + CSQTT installer.
# wdtt-server — VPN + admin API (обновляем с APK / своим бинарником).
# qwdtt-panel — HTTPS :46102 + SOCKS5 TPROXY + мост CSQTT (отдельный unit).
# CSQTT: deploy.sh / binary / cargo (см. ниже).
#
#   curl -fsSL https://raw.githubusercontent.com/MaxPain99/qwdtt-panel/master/install.sh | sudo bash
set -euo pipefail

readonly SCRIPT_VERSION="4.0"
readonly REPO_URL="${QWDTT_REPO:-https://github.com/MaxPain99/qwdtt-panel.git}"
readonly REPO_BRANCH="${QWDTT_BRANCH:-master}"
readonly SRC_DIR="${QWDTT_SRC_DIR:-/opt/qwdtt-panel}"
readonly BIN_PATH="/usr/local/bin/wdtt-server"
readonly PANEL_BIN_PATH="/usr/local/bin/qwdtt-panel"
readonly CONFIG_DIR="/etc/wdtt"
readonly LOG_FILE="/var/log/qwdtt-panel-install.log"
readonly CRED_FILE="${CONFIG_DIR}/credentials.txt"
readonly UNIT_PATH="/etc/systemd/system/wdtt.service"
readonly PANEL_UNIT_PATH="/etc/systemd/system/qwdtt-panel.service"
readonly GO_VERSION="${QWDTT_GO_VERSION:-1.25.0}"

readonly CSQTT_REPO_URL="${CSQTT_REPO:-https://github.com/amurcanov/csqtt.git}"
readonly CSQTT_SRC_DIR="${CSQTT_SRC_DIR:-/opt/csqtt-src}"
readonly CSQTT_BIN="/usr/local/bin/csqtt"
readonly CSQTT_CONFIG_DIR="/etc/csqtt"
readonly CSQTT_ENV_FILE="${CSQTT_CONFIG_DIR}/csqtt.env"
readonly CSQTT_UNIT_PATH="/etc/systemd/system/csqtt.service"
readonly CSQTT_PEER_PORT="${CSQTT_PEER_PORT:-46000}"
readonly CSQTT_WEB_PORT="${CSQTT_WEB_PORT:-46002}"
readonly CSQTT_SSH_PORT="${CSQTT_SSH_PORT:-22}"
readonly CSQTT_DEPLOY_URL="${CSQTT_DEPLOY_URL:-https://raw.githubusercontent.com/amurcanov/csqtt/main/app/src/main/assets/deploy.sh}"
# 1 = try cargo build if no binary; 0 = require existing binary / URL /tmp/csqtt
readonly CSQTT_BUILD="${CSQTT_BUILD:-1}"

WEB_PORT="${QWDTT_WEB_PORT:-46102}"
WEB_USER="${QWDTT_WEB_USER:-admin}"
OWNER_PASS="${QWDTT_PASSWORD:-}"
WEB_PASS="${QWDTT_WEB_PASS:-}"
CSQTT_WEB_USER="${CSQTT_WEB_USER:-admin}"
CSQTT_WEB_PASS="${CSQTT_WEB_PASS:-}"
CSQTT_MAIN_PASS="${CSQTT_MAIN_PASS:-}"
SKIP_CSQTT="${SKIP_CSQTT:-0}"

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
            apt-get install -y -qq ca-certificates curl git openssl iproute2 iptables procps \
                build-essential pkg-config cmake clang >>"$LOG_FILE" 2>&1 \
                || die "apt: не удалось поставить пакеты"
            ;;
        fedora)
            dnf install -y ca-certificates curl git openssl iproute iptables procps-ng \
                gcc make pkgconf-pkg-config cmake clang >>"$LOG_FILE" 2>&1 \
                || die "dnf: не удалось поставить пакеты"
            ;;
        centos|rhel|rocky|almalinux|oracle)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y ca-certificates curl git openssl iproute iptables procps-ng \
                    gcc make pkgconf-pkg-config cmake clang >>"$LOG_FILE" 2>&1 \
                    || die "dnf: не удалось поставить пакеты"
            else
                yum install -y ca-certificates curl git openssl iproute iptables procps-ng \
                    gcc make pkgconfig cmake clang >>"$LOG_FILE" 2>&1 \
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
        go build -tags qwdtt_panel -trimpath -ldflags '-s -w' -o /tmp/qwdtt-panel ./server
    ) >>"$LOG_FILE" 2>&1 || die "сборка не удалась, см. $LOG_FILE"
    install -m 0755 /tmp/wdtt-server "$BIN_PATH"
    install -m 0755 /tmp/qwdtt-panel "$PANEL_BIN_PATH"
    rm -f /tmp/wdtt-server /tmp/qwdtt-panel
    log_info "бинарники $BIN_PATH + $PANEL_BIN_PATH"
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
}

write_credentials() {
    cat > "$CRED_FILE" <<EOF
PANEL_URL=https://$(public_ip):${WEB_PORT}
WEB_USER=${WEB_USER}
WEB_PASS=${WEB_PASS}
OWNER_PASSWORD=${OWNER_PASS}
CSQTT_PEER_PORT=${CSQTT_PEER_PORT}
CSQTT_WEB_PORT=${CSQTT_WEB_PORT}
CSQTT_WEB_USER=${CSQTT_WEB_USER}
CSQTT_WEB_PASS=${CSQTT_WEB_PASS}
CSQTT_MAIN_PASS=${CSQTT_MAIN_PASS}
CSQTT_ENV=${CSQTT_ENV_FILE}
EOF
    chmod 600 "$CRED_FILE"
}

write_unit() {
    local src="${SRC_DIR}/packaging/wdtt.service"
    local panel_src="${SRC_DIR}/packaging/panel.service"
    [ -f "$src" ] || die "нет $src"
    [ -f "$panel_src" ] || die "нет $panel_src"
    install -m 0644 "$src" "$UNIT_PATH"
    install -m 0644 "$panel_src" "$PANEL_UNIT_PATH"
    systemctl daemon-reload
    systemctl unmask wdtt qwdtt-panel >/dev/null 2>&1 || true
    systemctl enable wdtt qwdtt-panel >/dev/null 2>&1 || true
    log_info "units: wdtt (VPN+admin) + qwdtt-panel (HTTPS:${WEB_PORT}+SOCKS)"
}

ensure_rust() {
    export PATH="${HOME}/.cargo/bin:/root/.cargo/bin:${PATH}"
    if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
        log_info "Rust: $(rustc --version 2>/dev/null | head -1)"
        return 0
    fi
    log_info "ставим rustup (для сборки CSQTT)..."
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable >>"$LOG_FILE" 2>&1 \
        || die "rustup не установился"
    # shellcheck disable=SC1091
    [ -f /root/.cargo/env ] && . /root/.cargo/env
    export PATH="/root/.cargo/bin:${PATH}"
    command -v cargo >/dev/null 2>&1 || die "cargo не найден после rustup"
}

fetch_csqtt_sources() {
    if [ -d "${CSQTT_SRC_DIR}/.git" ]; then
        git -C "$CSQTT_SRC_DIR" remote set-url origin "$CSQTT_REPO_URL" >>"$LOG_FILE" 2>&1 || true
        git -C "$CSQTT_SRC_DIR" fetch --depth 1 origin HEAD >>"$LOG_FILE" 2>&1 || die "git fetch csqtt"
        git -C "$CSQTT_SRC_DIR" checkout -q FETCH_HEAD >>"$LOG_FILE" 2>&1 || die "git checkout csqtt"
    else
        rm -rf "$CSQTT_SRC_DIR"
        git clone --depth 1 "$CSQTT_REPO_URL" "$CSQTT_SRC_DIR" >>"$LOG_FILE" 2>&1 || die "git clone csqtt"
    fi
    [ -d "${CSQTT_SRC_DIR}/csqtt-uring" ] || die "нет ${CSQTT_SRC_DIR}/csqtt-uring"
}

csqtt_host_gnu_target() {
    case "$(uname -m)" in
        x86_64|amd64) printf '%s' "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) printf '%s' "aarch64-unknown-linux-gnu" ;;
        *) die "архитектура $(uname -m) для сборки CSQTT не поддерживается" ;;
    esac
}

# Upstream uring_io.rs кастует MSG_DONTWAIT в u32 (под musl). На glibc sendmmsg ждёт i32.
patch_csqtt_gnu() {
    local f="${CSQTT_SRC_DIR}/csqtt-uring/uring_io.rs"
    [ -f "$f" ] || return 0
    if grep -q 'MSG_DONTWAIT as u32' "$f" 2>/dev/null; then
        sed -i 's/libc::MSG_DONTWAIT as u32/libc::MSG_DONTWAIT as _/g' "$f"
        log_info "патч glibc: MSG_DONTWAIT as _ в uring_io.rs"
    fi
}

build_csqtt_binary() {
    ensure_rust
    ensure_lowmem_swap
    fetch_csqtt_sources
    patch_csqtt_gnu
    # Upstream .cargo/config.toml по умолчанию тянет musl без zig/musl-gcc —
    # на VPS собираем под системный glibc (gnu), этого достаточно для systemd.
    local triple jobs
    triple="$(csqtt_host_gnu_target)"
    jobs="$(cargo_jobs_for_ram)"
    log_info "сборка CSQTT (cargo release, target=${triple}, jobs=${jobs})..."
    (
        cd "${CSQTT_SRC_DIR}/csqtt-uring"
        # Не даём config.toml подменить target на musl.
        if [ -f .cargo/config.toml ]; then
            mv -f .cargo/config.toml .cargo/config.toml.qwdtt-bak
        fi
        # shellcheck disable=SC1091
        [ -f /root/.cargo/env ] && . /root/.cargo/env
        export PATH="/root/.cargo/bin:${HOME}/.cargo/bin:${PATH}"
        export CARGO_BUILD_JOBS="$jobs"
        rustup target add "$triple" >>"$LOG_FILE" 2>&1 || true
        set +e
        cargo build --release --target "$triple" >>"$LOG_FILE" 2>&1
        status=$?
        set -e
        if [ -f .cargo/config.toml.qwdtt-bak ]; then
            mv -f .cargo/config.toml.qwdtt-bak .cargo/config.toml
        fi
        exit "$status"
    ) || die "сборка CSQTT не удалась, см. $LOG_FILE (или задайте CSQTT_BIN_URL / положите /tmp/csqtt)"
    local built=""
    for p in \
        "${CSQTT_SRC_DIR}/csqtt-uring/target/${triple}/release/csqtt" \
        "${CSQTT_SRC_DIR}/csqtt-uring/target/release/csqtt" \
        "${CSQTT_SRC_DIR}/target/release/csqtt"
    do
        [ -x "$p" ] && built="$p" && break
    done
    [ -n "$built" ] || die "после сборки нет бинарника csqtt"
    install -m 0755 "$built" "$CSQTT_BIN"
    install -m 0755 "$built" /tmp/csqtt
    # target/ легко съедает гигабайты и провоцирует OOM/полную диск.
    rm -rf "${CSQTT_SRC_DIR}/csqtt-uring/target" 2>/dev/null || true
    log_info "установлен $CSQTT_BIN (${triple})"
}

mem_total_mb() {
    awk '/MemTotal:/ {printf "%d", $2/1024; exit}' /proc/meminfo 2>/dev/null || echo 0
}

swap_total_mb() {
    awk '/SwapTotal:/ {printf "%d", $2/1024; exit}' /proc/meminfo 2>/dev/null || echo 0
}

# Сборка aws-lc + cargo на 1 ГБ RAM часто вешает VPS. Даём swap заранее.
ensure_lowmem_swap() {
    local mem swap need=2048
    mem="$(mem_total_mb)"
    swap="$(swap_total_mb)"
    log_info "RAM=${mem}M swap=${swap}M"
    if [ "$mem" -ge 3000 ]; then
        return 0
    fi
    if [ "$swap" -ge 1500 ]; then
        return 0
    fi
    if [ -f /swapfile-qwdtt ] || swapon --show=NAME --noheadings 2>/dev/null | grep -q .; then
        log_info "swap уже есть"
        return 0
    fi
    log_warn "мало RAM — создаю /swapfile-qwdtt (${need}M), иначе сборка CSQTT может повесить VPS"
    fallocate -l "${need}M" /swapfile-qwdtt 2>/dev/null \
        || dd if=/dev/zero of=/swapfile-qwdtt bs=1M count="$need" status=none
    chmod 600 /swapfile-qwdtt
    mkswap /swapfile-qwdtt >/dev/null
    swapon /swapfile-qwdtt
    grep -q swapfile-qwdtt /etc/fstab 2>/dev/null \
        || echo '/swapfile-qwdtt none swap sw 0 0' >> /etc/fstab
}

cargo_jobs_for_ram() {
    local mem
    mem="$(mem_total_mb)"
    if [ "$mem" -lt 1800 ]; then
        echo 1
    elif [ "$mem" -lt 3200 ]; then
        echo 2
    else
        echo "${CARGO_BUILD_JOBS:-$(nproc 2>/dev/null || echo 2)}"
    fi
}

# Официальный deploy.sh ставит nf_conntrack_max=1048576 — на 1–2 ГБ VPS это OOM.
soften_csqtt_sysctl() {
    local mem max=262144 f="/etc/sysctl.d/99-csqtt.conf"
    mem="$(mem_total_mb)"
    if [ "$mem" -lt 1500 ]; then
        max=65536
    elif [ "$mem" -lt 3000 ]; then
        max=131072
    fi
    if [ -f "$f" ] && grep -q nf_conntrack_max "$f" 2>/dev/null; then
        sed -i "s/net.netfilter.nf_conntrack_max *= *[0-9]*/net.netfilter.nf_conntrack_max = ${max}/" "$f" || true
    fi
    sysctl -w "net.netfilter.nf_conntrack_max=${max}" >/dev/null 2>&1 || true
    log_info "conntrack_max=${max} (смягчено под ${mem}M RAM)"
}

patch_deploy_sh_for_small_vps() {
    local sh="$1" mem max=262144
    mem="$(mem_total_mb)"
    if [ "$mem" -lt 1500 ]; then
        max=65536
    elif [ "$mem" -lt 3000 ]; then
        max=131072
    fi
    # Не даём deploy.sh выставить миллион conntrack на слабый VPS.
    sed -i "s/net.netfilter.nf_conntrack_max = 1048576/net.netfilter.nf_conntrack_max = ${max}/" "$sh" || true
}

# Кладёт рабочий бинарник в /tmp/csqtt (как Android перед deploy.sh).
stage_csqtt_binary_for_deploy() {
    if [ -n "${CSQTT_BIN_URL:-}" ]; then
        log_info "скачиваю CSQTT: $CSQTT_BIN_URL"
        curl -fL --retry 3 -o /tmp/csqtt "$CSQTT_BIN_URL" || die "не скачать CSQTT_BIN_URL"
        chmod +x /tmp/csqtt
        return 0
    fi
    if [ -f /tmp/csqtt ] && [ -x /tmp/csqtt ]; then
        log_info "берём /tmp/csqtt"
        return 0
    fi
    if [ -x "$CSQTT_BIN" ]; then
        install -m 0755 "$CSQTT_BIN" /tmp/csqtt
        log_info "staging $CSQTT_BIN → /tmp/csqtt"
        return 0
    fi
    if [ "$CSQTT_BUILD" = "1" ]; then
        build_csqtt_binary
        [ -x /tmp/csqtt ] || install -m 0755 "$CSQTT_BIN" /tmp/csqtt
        return 0
    fi
    die "нет CSQTT: положите /tmp/csqtt, задайте CSQTT_BIN_URL или CSQTT_BUILD=1"
}

prepare_csqtt_deploy_files() {
    if [ -z "$CSQTT_WEB_PASS" ] && [ -s "$CSQTT_ENV_FILE" ]; then
        CSQTT_WEB_PASS="$(grep -E '^CSQTT_WEB_PASS=' "$CSQTT_ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)"
        CSQTT_WEB_USER="$(grep -E '^CSQTT_WEB_USER=' "$CSQTT_ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)"
    fi
    [ -n "${CSQTT_WEB_USER:-}" ] || CSQTT_WEB_USER="admin"
    [ -n "${CSQTT_WEB_PASS:-}" ] || CSQTT_WEB_PASS="$WEB_PASS"
    [ -n "$CSQTT_WEB_PASS" ] || CSQTT_WEB_PASS="$(rand_pass 16)"

    if [ -z "$CSQTT_MAIN_PASS" ] && [ -s "$CRED_FILE" ]; then
        CSQTT_MAIN_PASS="$(grep -E '^CSQTT_MAIN_PASS=' "$CRED_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)"
    fi
    [ -n "$CSQTT_MAIN_PASS" ] || CSQTT_MAIN_PASS="$(rand_pass 18)"

    # Как Android-клиент: /tmp/csqtt.env + /tmp/csqtt-deploy.json перед deploy.sh
    cat > /tmp/csqtt.env <<EOF
CSQTT_WEB_USER=${CSQTT_WEB_USER}
CSQTT_WEB_PASS=${CSQTT_WEB_PASS}
CSQTT_SECURE_COOKIE=false
EOF
    chmod 600 /tmp/csqtt.env

    local device_id dns_value
    device_id="qwdtt-panel-$(hostname -s 2>/dev/null || echo vps)"
    dns_value="${CSQTT_DNS:-1.1.1.1,1.0.0.1}"
    cat > /tmp/csqtt-deploy.json <<EOF
{"main_password":"${CSQTT_MAIN_PASS}","device_id":"${device_id}","dns":"${dns_value}"}
EOF
    chmod 600 /tmp/csqtt-deploy.json
}

run_official_csqtt_deploy() {
    log_info "скачиваю официальный deploy.sh CSQTT..."
    curl -fL --retry 3 -o /tmp/csqtt-deploy.sh "$CSQTT_DEPLOY_URL" \
        || die "не скачать $CSQTT_DEPLOY_URL"
    chmod +x /tmp/csqtt-deploy.sh
    patch_deploy_sh_for_small_vps /tmp/csqtt-deploy.sh
    log_info "запуск amurcanov/csqtt deploy.sh (systemd)..."
    # Тот же вызов, что делает Android DeployOperations.
    env CSQTT_PEER_PORT="$CSQTT_PEER_PORT" \
        CSQTT_SSH_PORT="$CSQTT_SSH_PORT" \
        CSQTT_WEB_PORT="$CSQTT_WEB_PORT" \
        CSQTT_DEPLOY_MODE=systemd \
        bash /tmp/csqtt-deploy.sh install >>"$LOG_FILE" 2>&1 \
        || die "deploy.sh CSQTT не удался, см. $LOG_FILE и /var/log/csqtt-install.log"
    rm -f /tmp/csqtt-deploy.sh
    soften_csqtt_sysctl
    log_info "официальный deploy.sh завершён"
}

open_firewall() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw allow 56000/udp >/dev/null 2>&1 || true
        ufw allow 56002/udp >/dev/null 2>&1 || true
        ufw allow 56003/udp >/dev/null 2>&1 || true
        ufw allow "${WEB_PORT}/tcp" >/dev/null 2>&1 || true
        ufw allow "${CSQTT_PEER_PORT}/udp" >/dev/null 2>&1 || true
        ufw allow "${CSQTT_WEB_PORT}/tcp" >/dev/null 2>&1 || true
    fi
}

install_csqtt_stack() {
    if [ "$SKIP_CSQTT" = "1" ]; then
        log_warn "SKIP_CSQTT=1 — CSQTT пропускаю"
        CSQTT_WEB_PASS="${CSQTT_WEB_PASS:-(skipped)}"
        CSQTT_MAIN_PASS="${CSQTT_MAIN_PASS:-(skipped)}"
        return 0
    fi
    stage_csqtt_binary_for_deploy
    prepare_csqtt_deploy_files
    run_official_csqtt_deploy
    if ! systemctl is-active --quiet csqtt; then
        log_error "csqtt не active после deploy.sh"
        journalctl -u csqtt -n 40 --no-pager | tee -a "$LOG_FILE" || true
        exit 1
    fi
    # подтянуть пароли из итогового env (deploy мог дописать URING_MODE)
    if [ -s "$CSQTT_ENV_FILE" ]; then
        CSQTT_WEB_PASS="$(grep -E '^CSQTT_WEB_PASS=' "$CSQTT_ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)"
        CSQTT_WEB_USER="$(grep -E '^CSQTT_WEB_USER=' "$CSQTT_ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)"
    fi
    log_info "csqtt.service активен (официальный deploy)"
}

update_csqtt_stack() {
    if [ "$SKIP_CSQTT" = "1" ]; then
        log_warn "SKIP_CSQTT=1 — CSQTT не обновляю"
        return 0
    fi
    if [ ! -x "$CSQTT_BIN" ] && [ -z "${CSQTT_BIN_URL:-}" ] && [ ! -f /tmp/csqtt ] && [ "$CSQTT_BUILD" != "1" ]; then
        log_warn "CSQTT ещё не установлен — полный install"
        install_csqtt_stack
        return 0
    fi
    # Обновление бинарника + повтор официального deploy (как переустановка с клиента).
    stage_csqtt_binary_for_deploy
    prepare_csqtt_deploy_files
    run_official_csqtt_deploy
    systemctl is-active --quiet csqtt && log_info "csqtt обновлён через deploy.sh" \
        || log_warn "csqtt не active — journalctl -u csqtt / /var/log/csqtt-install.log"
}

do_install() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== installer v${SCRIPT_VERSION} $(date -Iseconds) ===" >>"$LOG_FILE"
    echo "qWDTT + CSQTT installer v${SCRIPT_VERSION}"
    os_packages
    install_go
    fetch_sources
    build_server
    mkdir -p /usr/local/lib/qwdtt
    [ -f "${SRC_DIR}/server/update-server.sh" ] && install -m 0755 "${SRC_DIR}/server/update-server.sh" /usr/local/lib/qwdtt/update-server.sh
    seed_secrets
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    write_unit
    open_firewall
    systemctl restart wdtt
    sleep 1
    systemctl restart qwdtt-panel
    sleep 2
    if ! systemctl is-active --quiet wdtt; then
        log_error "wdtt не запустился"
        journalctl -u wdtt -n 40 --no-pager | tee -a "$LOG_FILE" || true
        exit 1
    fi
    if ! systemctl is-active --quiet qwdtt-panel; then
        log_error "qwdtt-panel не запустился"
        journalctl -u qwdtt-panel -n 40 --no-pager | tee -a "$LOG_FILE" || true
        exit 1
    fi
    install_csqtt_stack
    write_credentials
    echo
    echo "qWDTT панель: https://$(public_ip):${WEB_PORT}  (сервис qwdtt-panel + SOCKS5)"
    echo "  логин:  ${WEB_USER}"
    echo "  пароль: ${WEB_PASS}"
    echo "  VPN:    ${OWNER_PASS}"
    echo "CSQTT:        peer UDP ${CSQTT_PEER_PORT}, web ${CSQTT_WEB_PORT}"
    echo "  web user: ${CSQTT_WEB_USER}"
    echo "  web pass: ${CSQTT_WEB_PASS}"
    echo "  VPN pass: ${CSQTT_MAIN_PASS}"
    echo "Учётки:       ${CRED_FILE}"
}

do_update() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "qWDTT + CSQTT installer v${SCRIPT_VERSION}"
    export PATH="/usr/local/go/bin:${PATH}"
    install_go
    fetch_sources
    build_server
    mkdir -p /usr/local/lib/qwdtt
    [ -f "${SRC_DIR}/server/update-server.sh" ] && install -m 0755 "${SRC_DIR}/server/update-server.sh" /usr/local/lib/qwdtt/update-server.sh
    seed_secrets
    # Миграция на split: ставим panel unit, wdtt без -web-port
    write_unit
    systemctl restart wdtt
    sleep 1
    systemctl restart qwdtt-panel
    if [ -s "${CONFIG_DIR}/web.password" ]; then
        WEB_PASS="$(tr -d '\r\n' < "${CONFIG_DIR}/web.password")"
    fi
    update_csqtt_stack
    if [ -s "$CSQTT_ENV_FILE" ]; then
        CSQTT_WEB_PASS="$(grep -E '^CSQTT_WEB_PASS=' "$CSQTT_ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)"
        CSQTT_WEB_USER="$(grep -E '^CSQTT_WEB_USER=' "$CSQTT_ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true)"
    fi
    [ -n "${OWNER_PASS:-}" ] || OWNER_PASS="$(tr -d '\r\n' < "${CONFIG_DIR}/main.password" 2>/dev/null || true)"
    [ -n "${WEB_PASS:-}" ] || WEB_PASS="$(tr -d '\r\n' < "${CONFIG_DIR}/web.password" 2>/dev/null || true)"
    write_credentials
    log_info "обновлено (wdtt + qwdtt-panel + csqtt)"
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
            systemctl restart qwdtt-panel
            if [ "$SKIP_CSQTT" != "1" ] && { [ -x "$CSQTT_BIN" ] || [ -f /tmp/csqtt ]; }; then
                stage_csqtt_binary_for_deploy
                prepare_csqtt_deploy_files
                run_official_csqtt_deploy
            fi
            ;;
        *) die "команды: install | update | write-unit" ;;
    esac
}

main "$@"
