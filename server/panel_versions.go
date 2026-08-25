package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Задаются через -ldflags при сборке (update-server.sh / CI).
// Префиксы нужны, чтобы найти строки в бинарнике без запуска
// (после -s -w символы сняты, значения остаются в .rodata).
const (
	buildVersionPrefix = "qwdtt-ver:"
	buildCommitPrefix  = "qwdtt-commit:"
)

var (
	BuildVersion = buildVersionPrefix + "dev"
	BuildCommit  = ""
	BuildTime    = ""
)

const (
	panelDefaultBin = "/usr/local/bin/qwdtt-panel"
	wdttDefaultBin  = "/usr/local/bin/wdtt-server"
	csqttDefaultBin = "/usr/local/bin/csqtt"
	qwdttTunCIDR    = "10.66.66.0/24"
	csqttTunCIDR    = "10.66.67.0/24"
	maxBinScan      = 80 << 20 // 80 MiB
)

var (
	binVerMu    sync.Mutex
	binVerCache = map[string]cachedBinVer{}
)

type cachedBinVer struct {
	at  time.Time
	val string
}

func stripStampPrefix(v, prefix string) string {
	v = strings.TrimSpace(v)
	return strings.TrimPrefix(v, prefix)
}

func panelDisplayVersion() string {
	v := stripStampPrefix(BuildVersion, buildVersionPrefix)
	if v == "" || v == "dev" {
		if b := binaryVersion(envOr(os.Getenv("QWDTT_PANEL_BIN"), panelDefaultBin)); b != "" && b != "—" {
			return b
		}
		return "dev"
	}
	c := stripStampPrefix(BuildCommit, buildCommitPrefix)
	if c != "" && !strings.Contains(v, c) {
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

// binaryVersion читает версию из файла на диске, не запуская бинарник.
// Порядок: stamp qwdtt-ver: → Go buildinfo (vcs) → mtime.
func binaryVersion(path string) string {
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
		if v := scanBinaryStamp(path, buildVersionPrefix); v != "" && v != "dev" {
			if c := scanBinaryStamp(path, buildCommitPrefix); c != "" && !strings.Contains(v, c) {
				val = truncateVersion(v + " (" + c + ")")
			} else {
				val = truncateVersion(v)
			}
		} else if v := goBuildInfoVersion(path); v != "" {
			val = v
		} else {
			val = "сборка " + st.ModTime().Local().Format("2006-01-02 15:04")
		}
	}
	binVerMu.Lock()
	binVerCache[path] = cachedBinVer{at: time.Now(), val: val}
	binVerMu.Unlock()
	return val
}

func scanBinaryStamp(path, prefix string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	needle := []byte(prefix)
	buf := make([]byte, 256*1024)
	var window []byte
	var read int64
	for read < maxBinScan {
		n, err := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			data := chunk
			if len(window) > 0 {
				data = append(window, chunk...)
			}
			if i := bytes.Index(data, needle); i >= 0 {
				if tok := takeVersionToken(data[i+len(needle):]); tok != "" {
					return tok
				}
			}
			keep := len(needle) - 1
			if keep < 0 {
				keep = 0
			}
			if keep > len(data) {
				keep = len(data)
			}
			window = append([]byte(nil), data[len(data)-keep:]...)
			read += int64(n)
		}
		if err == io.EOF || err != nil || n == 0 {
			break
		}
	}
	return ""
}

func takeVersionToken(b []byte) string {
	var out strings.Builder
	for _, c := range b {
		if c == 0 || c < 32 || c > 126 {
			break
		}
		if c == ' ' || c == '\t' || c == '"' || c == '\'' {
			break
		}
		out.WriteByte(c)
		if out.Len() >= 80 {
			break
		}
	}
	return strings.TrimSpace(out.String())
}

func goBuildInfoVersion(path string) string {
	bi, err := buildinfo.ReadFile(path)
	if err != nil || bi == nil {
		return ""
	}
	var rev, vcsTime string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = strings.TrimSpace(s.Value)
		case "vcs.time":
			vcsTime = strings.TrimSpace(s.Value)
		}
	}
	mainVer := strings.TrimSpace(bi.Main.Version)
	if mainVer != "" && mainVer != "(devel)" {
		if rev != "" && len(rev) >= 7 && !strings.Contains(mainVer, rev[:7]) {
			return truncateVersion(mainVer + " (" + rev[:7] + ")")
		}
		return truncateVersion(mainVer)
	}
	if rev != "" {
		short := rev
		if len(short) > 7 {
			short = short[:7]
		}
		if t := formatVCSTime(vcsTime); t != "" {
			return truncateVersion(short + " · " + t)
		}
		return truncateVersion(short)
	}
	return ""
}

func formatVCSTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Local().Format("2006-01-02")
		}
	}
	if len(s) >= 10 {
		return s[:10]
	}
	return s
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
