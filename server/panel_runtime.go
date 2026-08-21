package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	panelLogFileName  = "runtime.log"
	panelLogMaxLines  = 400
	panelLogMaxBytes  = 2 << 20
)

type panelLogWriter struct {
	enabled atomic.Bool
	mu      sync.Mutex
	path    string
	file    *os.File
	lines   []string
}

var runtimeLog = &panelLogWriter{}

func initPanelLogging(dir string, enabled bool) {
	runtimeLog.path = filepath.Join(dir, panelLogFileName)
	runtimeLog.enabled.Store(enabled)
	f, err := os.OpenFile(runtimeLog.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		runtimeLog.file = f
	}
	runtimeLog.lines = readLogTail(runtimeLog.path, panelLogMaxLines)
	log.SetOutput(runtimeLog)
}

func readLogTail(path string, max int) []string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	parts := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	out := make([]string, 0, max)
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

func (w *panelLogWriter) Write(p []byte) (int, error) {
	if !w.enabled.Load() {
		return len(p), nil
	}
	_, _ = os.Stderr.Write(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		if st, err := w.file.Stat(); err == nil && st.Size() > panelLogMaxBytes {
			_ = w.file.Close()
			_ = os.Truncate(w.path, 0)
			w.file, _ = os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		}
		if w.file != nil {
			_, _ = w.file.Write(p)
		}
	}
	s := strings.TrimRight(string(p), "\n")
	if s != "" {
		w.lines = append(w.lines, s)
		if len(w.lines) > panelLogMaxLines {
			w.lines = w.lines[len(w.lines)-panelLogMaxLines:]
		}
	}
	return len(p), nil
}

func panelLogsEnabled() bool {
	return runtimeLog.enabled.Load()
}

func panelLogText() string {
	runtimeLog.mu.Lock()
	defer runtimeLog.mu.Unlock()
	if len(runtimeLog.lines) == 0 {
		return ""
	}
	return strings.Join(runtimeLog.lines, "\n")
}

func panelLogsClear() error {
	runtimeLog.mu.Lock()
	defer runtimeLog.mu.Unlock()
	runtimeLog.lines = nil
	if runtimeLog.file != nil {
		_ = runtimeLog.file.Close()
	}
	if runtimeLog.path == "" {
		return nil
	}
	if err := os.Truncate(runtimeLog.path, 0); err != nil && !os.IsNotExist(err) {
		f, err2 := os.OpenFile(runtimeLog.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err2 != nil {
			return err
		}
		runtimeLog.file = f
		return nil
	}
	f, err := os.OpenFile(runtimeLog.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	runtimeLog.file = f
	return nil
}

func panelLogsSet(on bool) error {
	runtimeLog.enabled.Store(on)
	panelStoreMu.Lock()
	defer panelStoreMu.Unlock()
	if panelStore != nil {
		v := on
		panelStore.LoggingActive = &v
	}
	return persistPanelStoreLocked()
}
