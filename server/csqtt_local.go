package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	csqttDefaultWebPort uint16 = 46002
	csqttEnvPath               = "/etc/csqtt/csqtt.env"
)

var (
	csqttCredCacheMu sync.Mutex
	csqttCredCacheAt time.Time
	csqttCredBase    string
	csqttCredUser    string
	csqttCredPass    string
	csqttCredProbe   csqttProbe
)

type csqttProbe struct {
	present   bool
	envPath   string
	envErr    error // nil if read ok (even if pass empty)
	envDenied bool
	webPort   uint16
}

func csqttLocalCreds() (base, user, pass string) {
	base, user, pass, _ = csqttLocalCredsProbe()
	return
}

func csqttLocalCredsProbe() (base, user, pass string, probe csqttProbe) {
	csqttCredCacheMu.Lock()
	defer csqttCredCacheMu.Unlock()
	if time.Since(csqttCredCacheAt) < 20*time.Second && csqttCredPass != "" {
		return csqttCredBase, csqttCredUser, csqttCredPass, csqttCredProbe
	}

	user = "admin"
	port := csqttDefaultWebPort
	probe = csqttProbe{envPath: csqttEnvPath, webPort: port}

	unitPaths := []string{
		"/etc/systemd/system/csqtt.service",
		"/lib/systemd/system/csqtt.service",
		"/usr/lib/systemd/system/csqtt.service",
	}
	envPaths := []string{csqttEnvPath}
	for _, u := range unitPaths {
		applyCsqttUnitFile(u, &port, &envPaths)
	}
	envReadOK := false
	for _, p := range uniqueNonEmpty(envPaths) {
		err := applyCsqttEnvFileErr(p, &user, &pass, &port)
		probe.envPath = p
		probe.envErr = err
		if err == nil {
			envReadOK = true
			break
		}
		if !os.IsNotExist(err) {
			log.Printf("[CSQTT] не прочитан %s: %v", p, err)
			if os.IsPermission(err) || strings.Contains(strings.ToLower(err.Error()), "permission") {
				probe.envDenied = true
			}
		}
	}
	applyCsqttProcess(&user, &pass, &port)
	if pass == "" && csqttMainPID() > 0 {
		applyCsqttJournalPass(&pass)
	}

	probe.webPort = port
	probe.present = pass != "" || envReadOK || csqttPresent(port)
	if !probe.present && (csqttPathExists(probe.envPath) || csqttUnitExists()) {
		probe.present = true
	}

	base = fmt.Sprintf("https://127.0.0.1:%d", port)
	csqttCredBase, csqttCredUser, csqttCredPass = base, user, pass
	csqttCredProbe = probe
	csqttCredCacheAt = time.Now()
	return
}

func csqttInvalidateCreds() {
	csqttCredCacheMu.Lock()
	csqttCredPass = ""
	csqttCredProbe = csqttProbe{}
	csqttCredCacheAt = time.Time{}
	csqttCredCacheMu.Unlock()
}

func applyCsqttEnvFileErr(path string, user, pass *string, port *uint16) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := parseEnvAssignment(line)
		if !ok {
			continue
		}
		applyCsqttEnvKV(k, v, user, pass, port)
	}
	return nil
}

func applyCsqttUnitFile(path string, port *uint16, envPaths *[]string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "EnvironmentFile=") {
			raw := strings.TrimPrefix(line, "EnvironmentFile=")
			raw = strings.TrimPrefix(raw, "-")
			raw = strings.TrimSpace(raw)
			if raw != "" && envPaths != nil {
				*envPaths = append(*envPaths, raw)
			}
			continue
		}
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			next := ""
			if i+1 < len(fields) {
				next = fields[i+1]
			}
			switch {
			case f == "--web-port" && next != "":
				if n, err := strconv.Atoi(next); err == nil && n > 0 && n <= 65535 {
					*port = uint16(n)
				}
			case strings.HasPrefix(f, "--web-port="):
				if n, err := strconv.Atoi(strings.TrimPrefix(f, "--web-port=")); err == nil && n > 0 && n <= 65535 {
					*port = uint16(n)
				}
			}
		}
	}
}

func applyCsqttProcess(user, pass *string, port *uint16) {
	pid := csqttMainPID()
	if pid <= 0 {
		return
	}
	root := fmt.Sprintf("/proc/%d/", pid)
	if env, err := os.ReadFile(root + "environ"); err == nil {
		for _, part := range bytes.Split(env, []byte{0}) {
			k, v, ok := parseEnvAssignment(string(part))
			if !ok {
				continue
			}
			applyCsqttEnvKV(k, v, user, pass, port)
		}
	}
	if cmd, err := os.ReadFile(root + "cmdline"); err == nil {
		args := bytes.Split(cmd, []byte{0})
		for i := 0; i < len(args); i++ {
			a := string(args[i])
			next := ""
			if i+1 < len(args) {
				next = string(args[i+1])
			}
			switch {
			case a == "--web-user" && next != "":
				*user = next
				i++
			case strings.HasPrefix(a, "--web-user="):
				*user = strings.TrimPrefix(a, "--web-user=")
			case a == "--web-pass" && next != "":
				*pass = next
				i++
			case strings.HasPrefix(a, "--web-pass="):
				*pass = strings.TrimPrefix(a, "--web-pass=")
			case a == "--web-port" && next != "":
				if n, err := strconv.Atoi(next); err == nil && n > 0 && n <= 65535 {
					*port = uint16(n)
				}
				i++
			case strings.HasPrefix(a, "--web-port="):
				if n, err := strconv.Atoi(strings.TrimPrefix(a, "--web-port=")); err == nil && n > 0 && n <= 65535 {
					*port = uint16(n)
				}
			}
		}
	}
}

func applyCsqttEnvKV(k, v string, user, pass *string, port *uint16) {
	switch strings.ToUpper(k) {
	case "CSQTT_WEB_USER":
		if v != "" {
			*user = v
		}
	case "CSQTT_WEB_PASS":
		if v != "" {
			*pass = v
		}
	case "CSQTT_WEB_PORT":
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
			*port = uint16(n)
		}
	}
}

func parseEnvAssignment(line string) (key, val string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	line = strings.TrimPrefix(line, "export ")
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.TrimSpace(line[i+1:])
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
	}
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

func csqttMainPID() int {
	if b, err := os.ReadFile("/run/csqtt.pid"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 1 {
			return n
		}
	}
	if out, err := runCmd("systemctl", "show", "-p", "MainPID", "--value", "csqtt"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil && n > 1 {
			return n
		}
	}
	if out, err := runCmd("systemctl", "show", "-p", "MainPID", "csqtt"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "MainPID=") {
				if n, err := strconv.Atoi(strings.TrimPrefix(line, "MainPID=")); err == nil && n > 1 {
					return n
				}
			}
			if n, err := strconv.Atoi(line); err == nil && n > 1 {
				return n
			}
		}
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "" || !unicode.IsDigit(rune(name[0])) {
			continue
		}
		base := filepath.Join("/proc", name)
		if comm, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
			c := strings.TrimSpace(string(comm))
			if c == "csqtt" || strings.HasPrefix(c, "csqtt") {
				n, _ := strconv.Atoi(name)
				return n
			}
		}
		if cmd, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
			s := string(bytes.ReplaceAll(cmd, []byte{0}, []byte{' '}))
			if strings.Contains(s, "/csqtt") || strings.Contains(s, "csqtt --") || strings.HasPrefix(strings.TrimSpace(s), "csqtt ") {
				n, _ := strconv.Atoi(name)
				return n
			}
		}
	}
	return 0
}

func applyCsqttJournalPass(pass *string) {
	if *pass != "" {
		return
	}
	out, err := runCmd("journalctl", "-u", "csqtt", "-b", "--no-pager", "-o", "cat", "-n", "400")
	if err != nil || out == "" {
		return
	}
	const mark = "generated web password:"
	last := ""
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(strings.ToLower(line), mark)
		if i < 0 {
			i = strings.Index(line, mark)
		}
		if i < 0 {
			continue
		}
		last = strings.TrimSpace(line[i+len(mark):])
	}
	if last != "" {
		*pass = last
	}
}

// csqttInstalled is kept for callers; presence is broader than a single binary path.
func csqttInstalled() bool {
	return csqttPresent(csqttDefaultWebPort)
}

func csqttPresent(webPort uint16) bool {
	bins := []string{
		"/usr/local/bin/csqtt",
		"/usr/bin/csqtt",
		"/opt/csqtt/csqtt",
	}
	for _, p := range bins {
		if csqttPathExists(p) {
			return true
		}
	}
	if _, err := exec.LookPath("csqtt"); err == nil {
		return true
	}
	if csqttUnitExists() {
		return true
	}
	if csqttPathExists(csqttEnvPath) || csqttPathExists("/etc/csqtt/passwords.json") || csqttPathExists("/etc/csqtt") {
		return true
	}
	if csqttMainPID() > 0 {
		return true
	}
	if webPort == 0 {
		webPort = csqttDefaultWebPort
	}
	return csqttWebListening(webPort)
}

func csqttUnitExists() bool {
	for _, p := range []string{
		"/etc/systemd/system/csqtt.service",
		"/lib/systemd/system/csqtt.service",
		"/usr/lib/systemd/system/csqtt.service",
	} {
		if csqttPathExists(p) {
			return true
		}
	}
	return false
}

func csqttPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func csqttWebListening(port uint16) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func uniqueNonEmpty(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
