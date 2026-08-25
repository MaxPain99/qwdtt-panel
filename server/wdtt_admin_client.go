package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Режим отдельной панели: CRUD qWDTT через admin API, не через in-process db.
var (
	panelAdminMu    sync.RWMutex
	panelAdminURL   string
	panelAdminToken string
	panelAdminHC    = &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // self-signed admin.crt
				MinVersion:         tls.VersionTLS12,
			},
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
)

func panelSetWdttAdmin(baseURL, token string) {
	panelAdminMu.Lock()
	defer panelAdminMu.Unlock()
	panelAdminURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	panelAdminToken = strings.TrimSpace(token)
}

func panelWdttAdminEnabled() bool {
	panelAdminMu.RLock()
	defer panelAdminMu.RUnlock()
	return panelAdminURL != "" && panelAdminToken != ""
}

func panelAdminDo(method, path string, form url.Values) ([]byte, int, error) {
	panelAdminMu.RLock()
	base := panelAdminURL
	token := panelAdminToken
	panelAdminMu.RUnlock()
	if base == "" || token == "" {
		return nil, 0, fmt.Errorf("wdtt admin API не настроен")
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := panelAdminHC.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, resp.StatusCode, nil
}

func panelAdminListPasswords() ([]adminPasswordView, error) {
	b, code, err := panelAdminDo(http.MethodGet, "/admin/passwords", nil)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		return nil, fmt.Errorf("admin HTTP %d: %s", code, strings.TrimSpace(string(b)))
	}
	var wrap struct {
		Passwords []adminPasswordView `json:"passwords"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		return nil, err
	}
	return wrap.Passwords, nil
}

func panelAdminCreatePassword(label, vkHash string, days, maxDevices int) (*adminPasswordView, error) {
	form := url.Values{}
	form.Set("vk_hash", vkHash)
	form.Set("label", label)
	form.Set("max_devices", fmt.Sprintf("%d", maxDevices))
	if days > 0 {
		form.Set("days", fmt.Sprintf("%d", days))
	} else {
		// unlimited — наш admin API принимает 0; иначе 365
		form.Set("days", "0")
	}
	form.Set("ports", "56000,56001,56002")
	b, code, err := panelAdminDo(http.MethodPost, "/admin/passwords", form)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	var view adminPasswordView
	if err := json.Unmarshal(b, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

func panelAdminDeletePassword(pass string) error {
	form := url.Values{}
	form.Set("password", pass)
	b, code, err := panelAdminDo(http.MethodPost, "/admin/passwords/delete", form)
	if err != nil {
		return err
	}
	if code >= 400 {
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	return nil
}

func panelAdminUpdatePassword(pass, label, vkHash string, days int, setDays bool, maxDevices int, setMax bool) error {
	form := url.Values{}
	form.Set("password", pass)
	form.Set("label", label)
	if vkHash != "" {
		form.Set("vk_hash", vkHash)
	}
	if setDays {
		form.Set("days", fmt.Sprintf("%d", days))
	}
	if setMax && maxDevices > 0 {
		form.Set("max_devices", fmt.Sprintf("%d", maxDevices))
	}
	b, code, err := panelAdminDo(http.MethodPost, "/admin/passwords/update", form)
	if err != nil {
		return err
	}
	if code >= 400 {
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	return nil
}

func panelAdminSetActive(pass string, active bool) error {
	form := url.Values{}
	form.Set("password", pass)
	path := "/admin/passwords/deactivate"
	if active {
		path = "/admin/passwords/activate"
	}
	b, code, err := panelAdminDo(http.MethodPost, path, form)
	if err != nil {
		return err
	}
	if code >= 400 {
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	return nil
}

func panelAdminResetTraffic(pass string) error {
	form := url.Values{}
	form.Set("password", pass)
	b, code, err := panelAdminDo(http.MethodPost, "/admin/passwords/reset-traffic", form)
	if err != nil {
		return err
	}
	if code >= 400 {
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	return nil
}

func panelAdminUnbindDevice(pass, deviceID string) error {
	form := url.Values{}
	form.Set("password", pass)
	form.Set("device_id", deviceID)
	b, code, err := panelAdminDo(http.MethodPost, "/admin/passwords/unbind-device", form)
	if err != nil {
		return err
	}
	if code >= 400 {
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	return nil
}

func panelAdminStatus() map[string]interface{} {
	b, code, err := panelAdminDo(http.MethodGet, "/admin/status", nil)
	if err != nil || code >= 400 {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func panelOwnerPassword(configDir string) string {
	if b, err := os.ReadFile(filepath.Join(configDir, "main.password")); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return ""
}
