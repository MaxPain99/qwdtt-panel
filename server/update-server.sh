#!/usr/bin/env bash
# Rebuild wdtt-server + qwdtt-panel from MaxPain99/qwdtt-panel (GitHub).
# Does not rewrite systemd unit files.
set -euo pipefail

readonly LOG_FILE="/var/log/qwdtt-panel-update.log"
readonly SRC_DIR="${QWDTT_SRC_DIR:-/opt/qwdtt-panel}"
readonly BIN_PATH="${QWDTT_BIN:-/usr/local/bin/wdtt-server}"
readonly PANEL_BIN_PATH="${QWDTT_PANEL_BIN:-/usr/local/bin/qwdtt-panel}"
readonly REPO_URL="${QWDTT_REPO:-https://github.com/MaxPain99/qwdtt-panel.git}"
readonly REPO_BRANCH="${QWDTT_BRANCH:-master}"
readonly HELPER="/usr/local/lib/qwdtt/update-server.sh"

mkdir -p "$(dirname "$LOG_FILE")" /usr/local/lib/qwdtt
exec >>"$LOG_FILE" 2>&1
echo "=== qWDTT self-update $(date -Iseconds) pid=$$ ==="

sleep 2
export PATH="/usr/local/go/bin:${PATH}"
export CGO_ENABLED=0
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

command -v git >/dev/null 2>&1 || { echo "git не найден"; exit 1; }
command -v go >/dev/null 2>&1 || { echo "go не найден"; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemctl не найден"; exit 1; }

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

if [ -f "${SRC_DIR}/server/update-server.sh" ]; then
  install -m 0755 "${SRC_DIR}/server/update-server.sh" "$HELPER"
fi

echo "бинарники обновлены, units не трогаю"
systemctl restart wdtt
sleep 1
systemctl restart qwdtt-panel || true
echo "=== готово $(date -Iseconds) ==="
