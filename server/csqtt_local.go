package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	csqttCredCacheMu sync.Mutex
	csqttCredCacheAt time.Time
	csqttCredBase    string
	csqttCredUser    string
	csqttCredPass    string
)

func csqttLocalCreds() (base, user, pass string) {
	csqttCredCacheMu.Lock()
	defer csqttCredCacheMu.Unlock()
	if time.Since(csqttCredCacheAt) < 20*time.Second && csqttCredPass != "" {
		return csqttCredBase, csqttCredUser, csqttCredPass
	}
	user = "admin"
	port := uint16(46002)
	applyCsqttUnitFile("/etc/systemd/system/csqtt.service", &port)
	applyCsqttEnvFile("/etc/csqtt/csqtt.env", &user, &pass, &port)
	applyCsqttProcess(&user, &pass, &port)
	if pass == "" && csqttMainPID() > 0 {
		applyCsqttJournalPass(&pass)
	}
	base = fmt.Sprintf("https://127.0.0.1:%d", port)
	csqttCredBase, csqttCredUser, csqttCredPass = base, user, pass
	csqttCredCacheAt = time.Now()
	return
}

func csqttInvalidateCreds() {
	csqttCredCacheMu.Lock()
	csqttCredPass = ""
	csqttCredCacheAt = time.Time{}
	csqttCredCacheMu.Unlock()
}

func applyCsqttEnvFile(path string, user, pass *string, port *uint16) {
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[CSQTT] не прочитан %s: %v", path, err)
		}
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := parseEnvAssignment(line)
		if !ok {
			continue
		}
		applyCsqttEnvKV(k, v, user, pass, port)
	}
}

func applyCsqttUnitFile(path string, port *uint16) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
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
	switch k {
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
		comm, err := os.ReadFile(filepath.Join("/proc", name, "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == "csqtt" {
			n, _ := strconv.Atoi(name)
			return n
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

func csqttInstalled() bool {
	if _, err := os.Stat("/usr/local/bin/csqtt"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/csqtt/passwords.json"); err == nil {
		return true
	}
	return csqttMainPID() > 0
}
