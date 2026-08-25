package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Задаются через -ldflags при сборке (update-server.sh / CI).
var (
	BuildVersion = "dev"
	BuildCommit  = ""
	BuildTime    = ""
)

const (
	panelDefaultBin = "/usr/local/bin/qwdtt-panel"
	wdttDefaultBin  = "/usr/local/bin/wdtt-server"
	csqttDefaultBin = "/usr/local/bin/csqtt"
	qwdttTunCIDR    = "10.66.66.0/24"
	csqttTunCIDR    = "10.66.67.0/24"
)

var (
	binVerMu    sync.Mutex
	binVerCache = map[string]cachedBinVer{}
)

type cachedBinVer struct {
	at  time.Time
	val string
}

func panelDisplayVersion() string {
	v := strings.TrimSpace(BuildVersion)
	if v == "" || v == "dev" {
		if b := binaryBuildStamp(envOr(os.Getenv("QWDTT_PANEL_BIN"), panelDefaultBin)); b != "" && b != "—" {
			return b
		}
		return "dev"
	}
	if c := strings.TrimSpace(BuildCommit); c != "" && !strings.Contains(v, c) {
		v = v + " (" + c + ")"
	}
	return v
}

func envOr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return strings.TrimSpace(def)
	}
	return strings.TrimSpace(v)
}

func ifaceUp(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

// binaryBuildStamp — только mtime файла. Нельзя запускать wdtt/csqtt:
// бинарники без --version поднимают демон и вешают /api/services.
func binaryBuildStamp(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "—"
	}
	binVerMu.Lock()
	if c, ok := binVerCache[path]; ok && time.Since(c.at) < 30*time.Second {
		binVerMu.Unlock()
		return c.val
	}
	binVerMu.Unlock()

	val := "—"
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		val = "сборка " + st.ModTime().Local().Format("2006-01-02 15:04")
	}
	binVerMu.Lock()
	binVerCache[path] = cachedBinVer{at: time.Now(), val: val}
	binVerMu.Unlock()
	return val
}

func truncateVersion(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 96 {
		return s[:93] + "..."
	}
	return s
}

func csqttVersionFromAPI(stats map[string]interface{}) string {
	if stats == nil {
		return ""
	}
	for _, k := range []string{"version", "ver", "build", "server_version"} {
		v, ok := stats[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if s := strings.TrimSpace(t); s != "" {
				return truncateVersion(s)
			}
		case float64:
			return fmt.Sprintf("%g", t)
		}
	}
	return ""
}

func invalidateBinaryVersionCache() {
	binVerMu.Lock()
	binVerCache = map[string]cachedBinVer{}
	binVerMu.Unlock()
}

func runCmdTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
