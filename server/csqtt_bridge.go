package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	csqttTunIface    = "csqtt1"
	csqttDefaultURL  = "https://127.0.0.1:46002"
	csqttDefaultPeer = 46000
	csqttCaesarShift = byte(47)
)

type csqttBridge struct {
	mu     sync.Mutex
	base   string
	user   string
	pass   string
	cookie string
	hc     *http.Client
}

type csqttClientInfo struct {
	Password        string `json:"password"`
	Down            int64  `json:"down"`
	Up              int64  `json:"up"`
	Expires         int64  `json:"expires"`
	Active          bool   `json:"active"`
	ActiveSessions  int    `json:"active_sessions"`
	VKHash          string `json:"vk_hash"`
	VKHashes        string `json:"vk_hashes"`
	Name            string `json:"name"`
	DTLSPort        uint16 `json:"dtls_port"`
	WGPort          uint16 `json:"wg_port"`
	LocalPort       uint16 `json:"local_port"`
	DeviceID        string `json:"device_id"`
	IP              string `json:"ip"`
}

var (
	csqttBr = &csqttBridge{
		hc: &http.Client{
			Timeout: 4 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				TLSHandshakeTimeout: 2 * time.Second,
			},
		},
	}
	csqttStatMu   sync.Mutex
	csqttStatAt   time.Time
	csqttStatVal  map[string]interface{}
)

func csqttCaesarEncode(s string) string {
	b := []byte(s)
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c + csqttCaesarShift
	}
	return "c1:" + base64.StdEncoding.EncodeToString(out)
}

func csqttNormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = csqttDefaultURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("неверный URL панели CSQTT")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("нужен http или https")
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return "", errors.New("CSQTT только на этом VPS: https://127.0.0.1:46002")
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(host, "46002")
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func csqttCredsFromStore() (url, user, pass string) {
	panelStoreMu.Lock()
	defer panelStoreMu.Unlock()
	if panelStore == nil {
		return csqttDefaultURL, "", ""
	}
	url = panelStore.CsqttURL
	user = panelStore.CsqttUser
	pass = panelStore.CsqttPass
	if url == "" {
		url = csqttDefaultURL
	}
	return
}

func (b *csqttBridge) loginLocked() error {
	if b.user == "" || b.pass == "" {
		return errors.New("укажите логин и пароль панели CSQTT")
	}
	body, _ := json.Marshal(map[string]string{
		"user": csqttCaesarEncode(b.user),
		"pass": csqttCaesarEncode(b.pass),
	})
	req, err := http.NewRequest(http.MethodPost, b.base+"/api/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		return fmt.Errorf("CSQTT недоступен: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusTooManyRequests {
		return errors.New("CSQTT: слишком много попыток входа, подождите")
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = "неверный логин или пароль CSQTT"
		}
		return errors.New(msg)
	}
	b.cookie = ""
	for _, c := range resp.Cookies() {
		if c.Name == "csqtt_session" && c.Value != "" {
			b.cookie = c.Value
		}
	}
	if b.cookie == "" {
		return errors.New("CSQTT не вернул сессию")
	}
	return nil
}

func (b *csqttBridge) do(method, path string, payload interface{}) ([]byte, int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.base == "" || b.user == "" || b.pass == "" {
		url, user, pass := csqttCredsFromStore()
		b.base, b.user, b.pass = url, user, pass
		b.cookie = ""
	}
	if b.base == "" || b.user == "" || b.pass == "" {
		return nil, 0, errors.New("сначала подключите панель CSQTT")
	}
	if b.cookie == "" {
		if err := b.loginLocked(); err != nil {
			return nil, 0, err
		}
	}
	raw, status, err := b.roundTripLocked(method, path, payload)
	if status == http.StatusUnauthorized {
		b.cookie = ""
		if err := b.loginLocked(); err != nil {
			return nil, 0, err
		}
		return b.roundTripLocked(method, path, payload)
	}
	return raw, status, err
}

func (b *csqttBridge) roundTripLocked(method, path string, payload interface{}) ([]byte, int, error) {
	var rdr io.Reader
	if payload != nil {
		bjson, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(bjson)
	}
	req, err := http.NewRequest(method, b.base+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(&http.Cookie{Name: "csqtt_session", Value: b.cookie})
	resp, err := b.hc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("CSQTT: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, nil
}

func (b *csqttBridge) reset(base, user, pass string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.base = base
	b.user = user
	b.pass = pass
	b.cookie = ""
}

func csqttPrepareSharedSocks() {
	if err := csqttDeactivateLocalProxy(); err != nil {
		log.Printf("[SOCKS] CSQTT свой прокси не выключен: %v — снимаю его TPROXY", err)
	} else {
		log.Println("[SOCKS] SOCKS CSQTT выключен, трафик csqtt1 идёт в общий")
	}
	socksClearCsqttTproxy()
}

func csqttDeactivateLocalProxy() error {
	_, user, pass := csqttCredsFromStore()
	if user == "" || pass == "" {
		return errors.New("нет логина CSQTT — выключите SOCKS в панели CSQTT вручную")
	}
	_, status, err := csqttBr.do(http.MethodPost, "/api/local-proxy/deactivate", map[string]string{})
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("CSQTT HTTP %d", status)
	}
	return nil
}

func csqttConnectLink(password string, peer uint16, hashes string) string {
	ip := getPublicIP()
	if peer == 0 {
		peer = csqttDefaultPeer
	}
	u := fmt.Sprintf("csqtt://connect?v=2&host=%s&peer=%d&password=%s",
		url.QueryEscape(ip), peer, url.QueryEscape(password))
	var hs []string
	for _, h := range strings.Split(hashes, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			hs = append(hs, url.QueryEscape(h))
		}
	}
	if len(hs) > 0 {
		u += "&hashes=" + strings.Join(hs, "+")
	}
	return u
}

func csqttPanelState() map[string]interface{} {
	rawURL, user, pass := csqttCredsFromStore()
	st := map[string]interface{}{
		"url":          rawURL,
		"user":         user,
		"has_password": pass != "",
		"connected":    false,
		"error":        "",
		"iface":        csqttTunIface,
		"iface_up":     csqttIfaceUp(),
	}
	if user == "" || pass == "" {
		st["error"] = "укажите логин и пароль панели CSQTT"
		return st
	}
	body, status, err := csqttBr.do(http.MethodGet, "/api/stats", nil)
	if err != nil {
		st["error"] = err.Error()
		return st
	}
	if status >= 400 {
		st["error"] = fmt.Sprintf("CSQTT HTTP %d: %s", status, strings.TrimSpace(string(body)))
		return st
	}
	var stats map[string]interface{}
	_ = json.Unmarshal(body, &stats)
	st["connected"] = true
	st["stats"] = stats
	return st
}

func csqttCachedStatus() map[string]interface{} {
	csqttStatMu.Lock()
	if time.Since(csqttStatAt) < 5*time.Second && csqttStatVal != nil {
		v := csqttStatVal
		csqttStatMu.Unlock()
		return v
	}
	stale := csqttStatVal
	csqttStatMu.Unlock()
	go func() {
		v := csqttPanelState()
		csqttStatMu.Lock()
		csqttStatVal = v
		csqttStatAt = time.Now()
		csqttStatMu.Unlock()
	}()
	if stale != nil {
		return stale
	}
	return map[string]interface{}{"connected": false, "error": "", "iface_up": csqttIfaceUp()}
}

func csqttIfaceUp() bool {
	_, err := os.Stat("/sys/class/net/" + csqttTunIface)
	return err == nil
}

func csqttListClients() ([]map[string]interface{}, error) {
	raw, status, err := csqttBr.do(http.MethodGet, "/api/clients", nil)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("CSQTT HTTP %d: %s", status, strings.TrimSpace(string(raw)))
	}
	var list []csqttClientInfo
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("CSQTT clients: %w", err)
	}
	out := make([]map[string]interface{}, 0, len(list))
	for _, c := range list {
		hashes := c.VKHashes
		if hashes == "" {
			hashes = c.VKHash
		}
		exp := ""
		if c.Expires > 0 {
			exp = time.Unix(c.Expires, 0).Format("2006-01-02")
		}
		out = append(out, map[string]interface{}{
			"label":        c.Name,
			"password":     c.Password,
			"owner":        c.Name == "Главный пароль",
			"up":           c.Up,
			"down":         c.Down,
			"active":       c.Active,
			"sessions":     c.ActiveSessions,
			"hashes":       hashes,
			"expires":      exp,
			"dtls_port":    c.DTLSPort,
			"csqtt_link":   csqttConnectLink(c.Password, c.DTLSPort, hashes),
			"deactivated":  !c.Active,
		})
	}
	return out, nil
}

func handlePanelCsqtt(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		writePanelJSON(w, csqttPanelState())
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	base, err := csqttNormalizeURL(r.FormValue("url"))
	if err != nil {
		writePanelError(w, http.StatusBadRequest, err.Error())
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	if user == "" {
		user = "admin"
	}
	pass := r.FormValue("password")
	panelStoreMu.Lock()
	if panelStore == nil {
		panelStoreMu.Unlock()
		writePanelError(w, http.StatusBadRequest, "нет panel.json")
		return
	}
	if pass == "" {
		pass = panelStore.CsqttPass
	}
	panelStore.CsqttURL = base
	panelStore.CsqttUser = user
	panelStore.CsqttPass = pass
	_ = persistPanelStoreLocked()
	panelStoreMu.Unlock()
	csqttBr.reset(base, user, pass)
	csqttStatMu.Lock()
	csqttStatAt = time.Time{}
	csqttStatMu.Unlock()
	st := csqttPanelState()
	if !st["connected"].(bool) {
		writePanelError(w, http.StatusBadGateway, fmt.Sprint(st["error"]))
		return
	}
	writePanelJSON(w, st)
}

func handlePanelCsqttClients(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		list, err := csqttListClients()
		if err != nil {
			writePanelError(w, http.StatusBadGateway, err.Error())
			return
		}
		writePanelJSON(w, map[string]interface{}{"clients": list})
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	name := strings.TrimSpace(r.FormValue("label"))
	if name == "" {
		name = strings.TrimSpace(r.FormValue("name"))
	}
	if name == "" {
		writePanelError(w, http.StatusBadRequest, "укажите имя")
		return
	}
	days, _ := strconv.Atoi(r.FormValue("days"))
	if days < 0 || days > 3650 {
		days = 30
	}
	hashes, err := parseCsqttVkHashes(r)
	if err != nil {
		writePanelError(w, http.StatusBadRequest, err.Error())
		return
	}
	peer := uint16(csqttDefaultPeer)
	if v := r.FormValue("dtls_port"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			writePanelError(w, http.StatusBadRequest, "порт CSQTT")
			return
		}
		peer = uint16(n)
	}
	payload := map[string]interface{}{
		"name":      name,
		"days":      days,
		"hash":      hashes,
		"dtls_port": peer,
		"wg_port":   46001,
		"local_port": 0,
	}
	raw, status, err := csqttBr.do(http.MethodPost, "/api/clients", payload)
	if err != nil {
		writePanelError(w, http.StatusBadGateway, err.Error())
		return
	}
	if status >= 400 {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = fmt.Sprintf("CSQTT HTTP %d", status)
		}
		writePanelError(w, http.StatusBadRequest, msg)
		return
	}
	var created struct {
		Password string `json:"password"`
		Expires  int64  `json:"expires"`
		DTLSPort uint16 `json:"dtls_port"`
		VKHashes string `json:"vk_hashes"`
	}
	_ = json.Unmarshal(raw, &created)
	if created.DTLSPort == 0 {
		created.DTLSPort = peer
	}
	if created.VKHashes == "" {
		created.VKHashes = hashes
	}
	writePanelJSON(w, map[string]interface{}{
		"password":   created.Password,
		"csqtt_link": csqttConnectLink(created.Password, created.DTLSPort, created.VKHashes),
	})
}

func parseCsqttVkHashes(r *http.Request) (string, error) {
	raw := make([]string, 0, 8)
	if v := strings.TrimSpace(r.FormValue("vk_hash")); v != "" {
		raw = append(raw, v)
	}
	for i := 1; i <= 6; i++ {
		if v := strings.TrimSpace(r.FormValue("vk_hash" + strconv.Itoa(i))); v != "" {
			raw = append(raw, v)
		}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 6)
	for _, chunk := range raw {
		for _, p := range strings.FieldsFunc(chunk, func(ru rune) bool {
			return ru == ',' || ru == ';' || ru == '\n' || ru == '\r' || ru == '\t' || ru == ' '
		}) {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			if len(p) < 16 {
				return "", fmt.Errorf("VK hash слишком короткий")
			}
			if len(out) >= 6 {
				return "", fmt.Errorf("максимум 6 VK hash для CSQTT")
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return "", fmt.Errorf("укажите VK hash")
	}
	return strings.Join(out, ","), nil
}

func handlePanelCsqttDelete(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	pass := strings.TrimSpace(r.FormValue("password"))
	if pass == "" {
		writePanelError(w, http.StatusBadRequest, "password")
		return
	}
	path := "/api/clients/" + url.PathEscape(pass)
	raw, status, err := csqttBr.do(http.MethodDelete, path, nil)
	if err != nil {
		writePanelError(w, http.StatusBadGateway, err.Error())
		return
	}
	if status >= 400 {
		writePanelError(w, http.StatusBadRequest, strings.TrimSpace(string(raw)))
		return
	}
	writePanelJSON(w, map[string]bool{"ok": true})
}

func handlePanelCsqttToggle(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if err := parsePanelForm(r); err != nil {
		writePanelError(w, http.StatusBadRequest, "form")
		return
	}
	pass := strings.TrimSpace(r.FormValue("password"))
	if pass == "" {
		writePanelError(w, http.StatusBadRequest, "password")
		return
	}
	path := "/api/clients/" + url.PathEscape(pass) + "/toggle"
	raw, status, err := csqttBr.do(http.MethodPost, path, map[string]string{})
	if err != nil {
		writePanelError(w, http.StatusBadGateway, err.Error())
		return
	}
	if status >= 400 {
		writePanelError(w, http.StatusBadRequest, strings.TrimSpace(string(raw)))
		return
	}
	writePanelJSON(w, map[string]bool{"ok": true})
}
