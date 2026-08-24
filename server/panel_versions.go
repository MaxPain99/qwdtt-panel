package main

import (
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
		if b := detectBinaryVersion(envOr(os.Getenv("QWDTT_PANEL_BIN"), panelDefaultBin)); b != "" && b != "—" {
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

func detectBinaryVersion(path string) string {
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
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		binVerMu.Lock()
		binVerCache[path] = cachedBinVer{at: time.Now(), val: val}
		binVerMu.Unlock()
		return val
	}
	val = "сборка " + st.ModTime().Local().Format("2006-01-02 15:04")
	for _, args := range [][]string{
		{"--version"},
		{"-version"},
		{"version"},
		{"-V"},
	} {
		out, runErr := exec.Command(path, args...).CombinedOutput()
		line := firstNonEmptyLine(string(out))
		if line == "" || looksLikeUsage(line) {
			continue
		}
		if runErr == nil || looksLikeVersionLine(line) {
			val = truncateVersion(line)
			break
		}
	}

	binVerMu.Lock()
	binVerCache[path] = cachedBinVer{at: time.Now(), val: val}
	binVerMu.Unlock()
	return val
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func looksLikeUsage(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "usage") ||
		strings.HasPrefix(l, "flag provided") ||
		strings.Contains(l, "unknown flag") ||
		strings.Contains(l, "unknown command")
}

func looksLikeVersionLine(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "version") ||
		strings.Contains(l, "v0.") ||
		strings.Contains(l, "v1.") ||
		strings.Contains(l, "csqtt") ||
		strings.Contains(l, "wdtt")
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
