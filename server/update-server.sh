#!/usr/bin/env bash
# Обновление с панели:
#   $1 target = qwdtt | panel | csqtt | all
#   $2 mode   = source | app  (app только для qwdtt/csqtt)
# Unit панели qwdtt-panel не удаляется.
set -euo pipefail

readonly TARGET="${1:-all}"
readonly MODE="${2:-source}"
readonly LOG_FILE="/var/log/qwdtt-panel-update.log"
readonly STATUS_FILE="/var/log/qwdtt-panel-update.status"
readonly SRC_DIR="${QWDTT_SRC_DIR:-/opt/qwdtt-panel}"
readonly BIN_PATH="${QWDTT_BIN:-/usr/local/bin/wdtt-server}"
readonly PANEL_BIN_PATH="${QWDTT_PANEL_BIN:-/usr/local/bin/qwdtt-panel}"
readonly REPO_URL="${QWDTT_REPO:-https://github.com/MaxPain99/qwdtt-panel.git}"
readonly REPO_BRANCH="${QWDTT_BRANCH:-master}"
readonly STOCK_REPO_URL="${WDTT_STOCK_REPO:-https://github.com/SpaceNeuroX/proxy-turn-vk-android.git}"
readonly STOCK_DIR="${WDTT_STOCK_DIR:-/opt/wdtt-upstream}"
readonly HELPER="/usr/local/lib/qwdtt/update-server.sh"
readonly UNIT_PATH="/etc/systemd/system/wdtt.service"
readonly PANEL_UNIT_PATH="/etc/systemd/system/qwdtt-panel.service"

readonly CSQTT_REPO_URL="${CSQTT_REPO:-https://github.com/amurcanov/csqtt.git}"
readonly CSQTT_SRC_DIR="${CSQTT_SRC_DIR:-/opt/csqtt-src}"
readonly CSQTT_BIN="${CSQTT_BIN_PATH:-/usr/local/bin/csqtt}"
readonly CSQTT_DEPLOY_URL="${CSQTT_DEPLOY_URL:-https://raw.githubusercontent.com/amurcanov/csqtt/main/app/src/main/assets/deploy.sh}"
readonly CSQTT_PEER_PORT="${CSQTT_PEER_PORT:-46000}"
readonly CSQTT_WEB_PORT="${CSQTT_WEB_PORT:-46002}"
readonly CSQTT_SSH_PORT="${CSQTT_SSH_PORT:-22}"
readonly CSQTT_ENV_FILE="${CSQTT_ENV_FILE:-/etc/csqtt/csqtt.env}"

mkdir -p "$(dirname "$LOG_FILE")" /usr/local/lib/qwdtt
exec >>"$LOG_FILE" 2>&1
echo running >"$STATUS_FILE"
trap 'echo error >"$STATUS_FILE"' ERR
echo "=== panel update target=${TARGET} mode=${MODE} $(date -Iseconds) pid=$$ ==="

sleep 2
export PATH="/usr/local/go/bin:/root/.cargo/bin:${HOME}/.cargo/bin:${PATH}"
export CGO_ENABLED=0
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

command -v git >/dev/null 2>&1 || { echo "git не найден"; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemctl не найден"; exit 1; }

refresh_helper() {
  if [ -f "${SRC_DIR}/server/update-server.sh" ]; then
    install -m 0755 "${SRC_DIR}/server/update-server.sh" "$HELPER"
  fi
}

go_ldflags() {
  local ver commit ts
  ver="$(git -C "$SRC_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)"
  commit="$(git -C "$SRC_DIR" rev-parse --short HEAD 2>/dev/null || true)"
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Префиксы qwdtt-ver:/qwdtt-commit: — панель читает их из бинарника без exec.
  printf -- "-s -w -X main.BuildVersion=qwdtt-ver:%s -X main.BuildCommit=qwdtt-commit:%s -X main.BuildTime=%s" "$ver" "$commit" "$ts"
}

ensure_panel_repo() {
  if [ -d "${SRC_DIR}/.git" ]; then
    git -C "$SRC_DIR" remote set-url origin "$REPO_URL" || true
    git -C "$SRC_DIR" fetch --depth 1 origin "$REPO_BRANCH"
    git -C "$SRC_DIR" checkout -q FETCH_HEAD
  else
    rm -rf "$SRC_DIR"
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SRC_DIR"
  fi
  [ -d "${SRC_DIR}/server" ] || { echo "нет ${SRC_DIR}/server"; exit 1; }
}

restore_units() {
  if [ -f "${SRC_DIR}/packaging/wdtt.service" ]; then
    install -m 0644 "${SRC_DIR}/packaging/wdtt.service" "$UNIT_PATH"
  fi
  if [ -f "${SRC_DIR}/packaging/panel.service" ]; then
    install -m 0644 "${SRC_DIR}/packaging/panel.service" "$PANEL_UNIT_PATH"
  fi
  systemctl daemon-reload
  systemctl enable wdtt qwdtt-panel >/dev/null 2>&1 || true
}

# --- qWDTT VPN-сервер (только wdtt-server) ---
update_qwdtt_source() {
  command -v go >/dev/null 2>&1 || { echo "go не найден"; exit 1; }
  ensure_panel_repo
  local ld
  ld="$(go_ldflags)"
  (
    cd "$SRC_DIR"
    go build -trimpath -ldflags "$ld" -o /tmp/wdtt-server ./server
  )
  install -m 0755 /tmp/wdtt-server "$BIN_PATH"
  rm -f /tmp/wdtt-server
  if [ -f "${SRC_DIR}/packaging/wdtt.service" ]; then
    install -m 0644 "${SRC_DIR}/packaging/wdtt.service" "$UNIT_PATH"
    systemctl daemon-reload
  fi
  echo "qWDTT: wdtt-server обновлён"
  systemctl restart wdtt
}

# --- панель (только qwdtt-panel) ---
update_panel_source() {
  command -v go >/dev/null 2>&1 || { echo "go не найден"; exit 1; }
  ensure_panel_repo
  local ld
  ld="$(go_ldflags)"
  (
    cd "$SRC_DIR"
    go build -tags qwdtt_panel -trimpath -ldflags "$ld" -o /tmp/qwdtt-panel ./server
  )
  install -m 0755 /tmp/qwdtt-panel "$PANEL_BIN_PATH"
  rm -f /tmp/qwdtt-panel
  refresh_helper
  if [ -f "${SRC_DIR}/packaging/panel.service" ]; then
    install -m 0644 "${SRC_DIR}/packaging/panel.service" "$PANEL_UNIT_PATH"
    systemctl daemon-reload
  fi
  echo "панель: qwdtt-panel обновлена"
  systemctl restart qwdtt-panel || true
}

# --- qWDTT: как из приложения (stock SpaceNeuroX server, панель не затираем) ---
update_qwdtt_app() {
  command -v go >/dev/null 2>&1 || { echo "go не найден"; exit 1; }
  if [ -d "${STOCK_DIR}/.git" ]; then
    git -C "$STOCK_DIR" remote set-url origin "$STOCK_REPO_URL" || true
    git -C "$STOCK_DIR" fetch --depth 1 origin HEAD
    git -C "$STOCK_DIR" checkout -q FETCH_HEAD
  else
    rm -rf "$STOCK_DIR"
    git clone --depth 1 "$STOCK_REPO_URL" "$STOCK_DIR"
  fi
  [ -d "${STOCK_DIR}/server" ] || { echo "нет ${STOCK_DIR}/server"; exit 1; }
  (
    cd "$STOCK_DIR"
    go build -trimpath -ldflags '-s -w' -o /tmp/wdtt-server ./server
  )
  install -m 0755 /tmp/wdtt-server "$BIN_PATH"
  rm -f /tmp/wdtt-server
  # Панель остаётся; unit с admin API — наш packaging
  if [ ! -d "${SRC_DIR}/server" ]; then
    ensure_panel_repo || true
  fi
  restore_units
  echo "qWDTT app: stock SpaceNeuroX wdtt-server (панель сохранена)"
  systemctl restart wdtt
  sleep 1
  systemctl try-restart qwdtt-panel || systemctl restart qwdtt-panel || true
}

csqtt_gnu_target() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
    *) echo ""; return 1 ;;
  esac
}

build_csqtt_cargo() {
  if ! command -v cargo >/dev/null 2>&1; then
    return 1
  fi
  if [ -d "${CSQTT_SRC_DIR}/.git" ]; then
    git -C "$CSQTT_SRC_DIR" remote set-url origin "$CSQTT_REPO_URL" || true
    git -C "$CSQTT_SRC_DIR" fetch --depth 1 origin HEAD
    git -C "$CSQTT_SRC_DIR" checkout -q FETCH_HEAD
  else
    rm -rf "$CSQTT_SRC_DIR"
    git clone --depth 1 "$CSQTT_REPO_URL" "$CSQTT_SRC_DIR"
  fi
  [ -d "${CSQTT_SRC_DIR}/csqtt-uring" ] || return 1
  local f="${CSQTT_SRC_DIR}/csqtt-uring/uring_io.rs"
  if [ -f "$f" ] && grep -q 'MSG_DONTWAIT as u32' "$f" 2>/dev/null; then
    sed -i 's/libc::MSG_DONTWAIT as u32/libc::MSG_DONTWAIT as _/g' "$f"
  fi
  local triple jobs=1 mem
  triple="$(csqtt_gnu_target)" || return 1
  mem="$(awk '/MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  if [ "$mem" -ge 3000 ]; then jobs=2; fi
  if [ "$mem" -ge 6000 ]; then jobs=4; fi
  # shellcheck disable=SC1091
  [ -f /root/.cargo/env ] && . /root/.cargo/env
  (
    cd "${CSQTT_SRC_DIR}/csqtt-uring"
    if [ -f .cargo/config.toml ]; then
      mv -f .cargo/config.toml .cargo/config.toml.qwdtt-bak
    fi
    export CARGO_BUILD_JOBS="$jobs"
    rustup target add "$triple" || true
    set +e
    cargo build --release --target "$triple"
    status=$?
    set -e
    if [ -f .cargo/config.toml.qwdtt-bak ]; then
      mv -f .cargo/config.toml.qwdtt-bak .cargo/config.toml
    fi
    exit "$status"
  )
  local built=""
  for p in \
    "${CSQTT_SRC_DIR}/csqtt-uring/target/${triple}/release/csqtt" \
    "${CSQTT_SRC_DIR}/csqtt-uring/target/release/csqtt"
  do
    [ -x "$p" ] && built="$p" && break
  done
  [ -n "$built" ] || return 1
  install -m 0755 "$built" "$CSQTT_BIN"
  install -m 0755 "$built" /tmp/csqtt
  rm -rf "${CSQTT_SRC_DIR}/csqtt-uring/target" 2>/dev/null || true
  return 0
}

stage_csqtt_binary() {
  if [ -n "${CSQTT_BIN_URL:-}" ]; then
    curl -fL --retry 3 -o /tmp/csqtt "$CSQTT_BIN_URL"
    chmod 0755 /tmp/csqtt
    return 0
  fi
  if build_csqtt_cargo; then
    return 0
  fi
  if [ -x "$CSQTT_BIN" ]; then
    install -m 0755 "$CSQTT_BIN" /tmp/csqtt
    return 0
  fi
  echo "CSQTT: нет бинарника (cargo / CSQTT_BIN_URL / $CSQTT_BIN)"
  return 1
}

# --- CSQTT: только бинарник (source) ---
update_csqtt_source() {
  if [ -n "${CSQTT_BIN_URL:-}" ]; then
    curl -fL --retry 3 -o /tmp/csqtt-new "$CSQTT_BIN_URL"
    install -m 0755 /tmp/csqtt-new "$CSQTT_BIN"
    rm -f /tmp/csqtt-new
  else
    build_csqtt_cargo || { echo "CSQTT source: сборка не удалась"; exit 1; }
  fi
  systemctl restart csqtt || true
  echo "CSQTT source: бинарник обновлён"
}

# --- CSQTT: как из приложения (официальный deploy.sh) ---
update_csqtt_app() {
  stage_csqtt_binary || exit 1
  mkdir -p /etc/csqtt
  if [ ! -s "$CSQTT_ENV_FILE" ]; then
    local web_user=admin web_pass
    web_pass="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16 || echo changeme)"
    cat >"$CSQTT_ENV_FILE" <<EOF
CSQTT_WEB_USER=${web_user}
CSQTT_WEB_PASS=${web_pass}
CSQTT_SECURE_COOKIE=false
EOF
    chmod 600 "$CSQTT_ENV_FILE"
  fi
  if [ ! -s /tmp/csqtt-deploy.json ]; then
    local main_pass device_id
    main_pass="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18 || echo mainpass)"
    device_id="$(cat /etc/machine-id 2>/dev/null | head -c 32 || echo paneldevice)"
    printf '{"main_password":"%s","device_id":"%s","dns":"1.1.1.1,1.0.0.1"}\n' "$main_pass" "$device_id" > /tmp/csqtt-deploy.json
    chmod 600 /tmp/csqtt-deploy.json
  fi
  curl -fL --retry 3 -o /tmp/csqtt-deploy.sh "$CSQTT_DEPLOY_URL"
  chmod +x /tmp/csqtt-deploy.sh
  # clamp conntrack on small VPS if deploy sets huge values
  if grep -q 'nf_conntrack_max' /tmp/csqtt-deploy.sh 2>/dev/null; then
    sed -i 's/1048576/262144/g' /tmp/csqtt-deploy.sh || true
  fi
  env CSQTT_PEER_PORT="$CSQTT_PEER_PORT" \
      CSQTT_SSH_PORT="$CSQTT_SSH_PORT" \
      CSQTT_WEB_PORT="$CSQTT_WEB_PORT" \
      CSQTT_DEPLOY_MODE=systemd \
      bash /tmp/csqtt-deploy.sh install
  rm -f /tmp/csqtt-deploy.sh
  systemctl is-active --quiet csqtt && echo "CSQTT app: deploy.sh OK" || echo "CSQTT app: проверьте journalctl -u csqtt"
}

update_qwdtt() {
  case "$MODE" in
    app) update_qwdtt_app ;;
    *) update_qwdtt_source ;;
  esac
}

update_csqtt() {
  case "$MODE" in
    app) update_csqtt_app ;;
    *) update_csqtt_source ;;
  esac
}

case "$TARGET" in
  qwdtt) update_qwdtt ;;
  panel) update_panel_source ;;
  csqtt) update_csqtt ;;
  all|both|"")
    update_qwdtt
    update_panel_source || echo "панель: ошибка/пропуск (см. лог)"
    update_csqtt || echo "CSQTT: ошибка/пропуск (см. лог)"
    ;;
  *)
    echo "unknown target: $TARGET"
    exit 1
    ;;
esac

echo "=== готово $(date -Iseconds) ==="
echo success >"$STATUS_FILE"
