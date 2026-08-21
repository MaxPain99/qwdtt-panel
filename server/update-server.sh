#!/usr/bin/env bash
# Обновление с GitHub: qwdtt | csqtt | all
# Unit-файлы не переписывает.
set -euo pipefail

readonly TARGET="${1:-all}"
readonly LOG_FILE="/var/log/qwdtt-panel-update.log"
readonly SRC_DIR="${QWDTT_SRC_DIR:-/opt/qwdtt-panel}"
readonly BIN_PATH="${QWDTT_BIN:-/usr/local/bin/wdtt-server}"
readonly PANEL_BIN_PATH="${QWDTT_PANEL_BIN:-/usr/local/bin/qwdtt-panel}"
readonly REPO_URL="${QWDTT_REPO:-https://github.com/MaxPain99/qwdtt-panel.git}"
readonly REPO_BRANCH="${QWDTT_BRANCH:-master}"
readonly HELPER="/usr/local/lib/qwdtt/update-server.sh"

readonly CSQTT_REPO_URL="${CSQTT_REPO:-https://github.com/amurcanov/csqtt.git}"
readonly CSQTT_SRC_DIR="${CSQTT_SRC_DIR:-/opt/csqtt-src}"
readonly CSQTT_BIN="${CSQTT_BIN_PATH:-/usr/local/bin/csqtt}"

mkdir -p "$(dirname "$LOG_FILE")" /usr/local/lib/qwdtt
exec >>"$LOG_FILE" 2>&1
echo "=== panel update target=${TARGET} $(date -Iseconds) pid=$$ ==="

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

update_qwdtt() {
  command -v go >/dev/null 2>&1 || { echo "go не найден"; exit 1; }
  if [ -d "${SRC_DIR}/.git" ]; then
    git -C "$SRC_DIR" remote set-url origin "$REPO_URL" || true
    git -C "$SRC_DIR" fetch --depth 1 origin "$REPO_BRANCH"
    git -C "$SRC_DIR" checkout -q FETCH_HEAD
  else
    rm -rf "$SRC_DIR"
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SRC_DIR"
  fi
  [ -d "${SRC_DIR}/server" ] || { echo "нет ${SRC_DIR}/server"; exit 1; }
  (
    cd "$SRC_DIR"
    go build -trimpath -ldflags '-s -w' -o /tmp/wdtt-server ./server
    go build -tags qwdtt_panel -trimpath -ldflags '-s -w' -o /tmp/qwdtt-panel ./server
  )
  install -m 0755 /tmp/wdtt-server "$BIN_PATH"
  install -m 0755 /tmp/qwdtt-panel "$PANEL_BIN_PATH"
  rm -f /tmp/wdtt-server /tmp/qwdtt-panel
  refresh_helper
  echo "qWDTT: бинарники обновлены"
  systemctl restart wdtt
  sleep 1
  systemctl restart qwdtt-panel || true
}

csqtt_gnu_target() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
    *) echo ""; return 1 ;;
  esac
}

update_csqtt() {
  if [ -n "${CSQTT_BIN_URL:-}" ]; then
    echo "CSQTT: скачиваю $CSQTT_BIN_URL"
    curl -fL --retry 3 -o /tmp/csqtt-new "$CSQTT_BIN_URL"
    install -m 0755 /tmp/csqtt-new "$CSQTT_BIN"
    rm -f /tmp/csqtt-new
    systemctl restart csqtt || true
    echo "CSQTT: бинарник из URL"
    return 0
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    if [ -x /tmp/csqtt ]; then
      install -m 0755 /tmp/csqtt "$CSQTT_BIN"
      systemctl restart csqtt || true
      echo "CSQTT: установлен из /tmp/csqtt (cargo нет)"
      return 0
    fi
    echo "CSQTT: нужен cargo, CSQTT_BIN_URL или /tmp/csqtt"
    exit 1
  fi

  if [ -d "${CSQTT_SRC_DIR}/.git" ]; then
    git -C "$CSQTT_SRC_DIR" remote set-url origin "$CSQTT_REPO_URL" || true
    git -C "$CSQTT_SRC_DIR" fetch --depth 1 origin HEAD
    git -C "$CSQTT_SRC_DIR" checkout -q FETCH_HEAD
  else
    rm -rf "$CSQTT_SRC_DIR"
    git clone --depth 1 "$CSQTT_REPO_URL" "$CSQTT_SRC_DIR"
  fi
  [ -d "${CSQTT_SRC_DIR}/csqtt-uring" ] || { echo "нет csqtt-uring"; exit 1; }

  local f="${CSQTT_SRC_DIR}/csqtt-uring/uring_io.rs"
  if [ -f "$f" ] && grep -q 'MSG_DONTWAIT as u32' "$f" 2>/dev/null; then
    sed -i 's/libc::MSG_DONTWAIT as u32/libc::MSG_DONTWAIT as _/g' "$f"
  fi

  local triple jobs=1 mem
  triple="$(csqtt_gnu_target)" || { echo "архитектура не поддерживается"; exit 1; }
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
  [ -n "$built" ] || { echo "нет бинарника csqtt после сборки"; exit 1; }
  install -m 0755 "$built" "$CSQTT_BIN"
  rm -rf "${CSQTT_SRC_DIR}/csqtt-uring/target" 2>/dev/null || true
  systemctl restart csqtt || true
  echo "CSQTT: собран и перезапущен"
}

case "$TARGET" in
  qwdtt) update_qwdtt ;;
  csqtt) update_csqtt ;;
  all|both|"")
    update_qwdtt
    update_csqtt || echo "CSQTT: обновление пропущено/ошибка (см. лог)"
    ;;
  *)
    echo "unknown target: $TARGET (qwdtt|csqtt|all)"
    exit 1
    ;;
esac

echo "=== готово $(date -Iseconds) ==="
