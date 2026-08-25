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
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"http/1.1"},
				},
				TLSHandshakeTimeout: 3 * time.Second,
				ForceAttemptHTTP2:   false,
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

func (b *csqttBridge) loginLocked() error {
	if b.user == "" || b.pass == "" {
		return errors.New("нет логина CSQTT")
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
	req.Header.Set("Accept", "application/json, text/plain, */*")
	resp, err := b.hc.Do(req)
	if err != nil {
		return fmt.Errorf("CSQTT недоступен на %s: %w", b.base, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
		return fmt.Errorf("CSQTT редирект с %s (HTTP %d)", b.base, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return errors.New("CSQTT: слишком много попыток входа, подождите 3 минуты")
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = fmt.Sprintf("вход CSQTT HTTP %d", resp.StatusCode)
		}
		return errors.New(msg)
	}
	b.cookie = csqttSessionCookie(resp)
	if b.cookie == "" {
		return errors.New("CSQTT не вернул сессию")
	}
	log.Printf("[CSQTT] панель %s, логин %s", b.base, b.user)
	return nil
}

func csqttSessionCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "csqtt_session" && c.Value != "" {
			return c.Value
		}
	}
	for _, raw := range resp.Header.Values("Set-Cookie") {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "csqtt_session=") {
				return strings.TrimPrefix(part, "csqtt_session=")
			}
		}
	}
	return ""
}

func (b *csqttBridge) applyLocalCredsLocked() error {
	base, user, pass, probe := csqttLocalCredsProbe()
	// Password from env/process is enough — treat CSQTT as available even if
	// binary path / passwords.json / PID heuristics fail.
	if pass == "" {
		if !probe.present && !csqttPresent(probe.webPort) {
			return errors.New("CSQTT на этом VPS не найден (нет unit/бинарника, /etc/csqtt и API на :46002)")
		}
		if probe.envDenied {
			return fmt.Errorf("нет доступа к %s — добавьте в wdtt.service ReadOnlyPaths=%s или права на чтение для пользователя сервиса",
				probe.envPath, "/etc/csqtt")
		}
		if probe.envErr != nil && !os.IsNotExist(probe.envErr) {
			return fmt.Errorf("не удалось прочитать %s: %v", probe.envPath, probe.envErr)
		}
		return fmt.Errorf("нет пароля CSQTT_WEB_PASS в %s — укажите пароль панели CSQTT и перезапустите csqtt", probe.envPath)
	}
	if b.base != base || b.user != user || b.pass != pass {
		b.base = base
		b.user = user
		b.pass = pass
		b.cookie = ""
	}
	return nil
}

func (b *csqttBridge) do(method, path string, payload interface{}) ([]byte, int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.applyLocalCredsLocked(); err != nil {
		return nil, 0, err
	}
	if b.cookie == "" {
		if err := b.loginLocked(); err != nil {
			b.cookie = ""
			csqttInvalidateCreds()
			_ = b.applyLocalCredsLocked()
			if err2 := b.loginLocked(); err2 != nil {
				return nil, 0, err
			}
		}
	}
	raw, status, err := b.roundTripLocked(method, path, payload)
	if status == http.StatusUnauthorized {
		b.cookie = ""
		csqttInvalidateCreds()
		if err := b.applyLocalCredsLocked(); err != nil {
			return nil, status, err
		}
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

func csqttPrepareSharedSocks() {
	if err := csqttDeactivateLocalProxy(); err != nil {
		log.Printf("[SOCKS] CSQTT свой прокси не выключен: %v — снимаю его TPROXY", err)
	} else {
		log.Println("[SOCKS] SOCKS CSQTT выключен, трафик csqtt1 идёт в общий")
	}
	socksClearCsqttTproxy()
}

func csqttDeactivateLocalProxy() error {
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
	st := map[string]interface{}{
		"connected": false,
		"error":     "",
		"iface":     csqttTunIface,
		"iface_up":  csqttIfaceUp(),
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
	if time.Since(csqttStatAt) < 2*time.Second && csqttStatVal != nil {
		v := csqttStatVal
		csqttStatMu.Unlock()
		return v
	}
	stale := csqttStatVal
	csqttStatMu.Unlock()
	// Синхронно при первой загрузке / устаревшем кэше — иначе панель
	// показывает нули, пока фоновый refresh не успел.
	if stale == nil || time.Since(csqttStatAt) > 10*time.Second {
		v := csqttPanelState()
		csqttStatMu.Lock()
		csqttStatVal = v
		csqttStatAt = time.Now()
		csqttStatMu.Unlock()
		return v
	}
	go func() {
		v := csqttPanelState()
		csqttStatMu.Lock()
		csqttStatVal = v
		csqttStatAt = time.Now()
		csqttStatMu.Unlock()
	}()
	return stale
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
			"device_id":    c.DeviceID,
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
	if r.Method != http.MethodGet {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	writePanelJSON(w, csqttPanelState())
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
	payload := map[string]interface{}{
		"name":       name,
		"days":       days,
		"hash":       hashes,
		"dtls_port":  peer,
		"wg_port":    46001,
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
	for i := 1; i <= 4; i++ {
		if v := strings.TrimSpace(r.FormValue("vk_hash" + strconv.Itoa(i))); v != "" {
			raw = append(raw, v)
		}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
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
			if len(out) >= 4 {
				return "", fmt.Errorf("максимум 4 VK hash")
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

func handlePanelCsqttUpdate(w http.ResponseWriter, r *http.Request) {
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
	payload := map[string]interface{}{
		"name":       name,
		"days":       days,
		"hash":       hashes,
		"vk_hashes":  hashes,
		"dtls_port":  peer,
		"wg_port":    46001,
		"local_port": 0,
	}
	path := "/api/clients/" + url.PathEscape(pass)
	raw, status, err := csqttBr.do(http.MethodPut, path, payload)
	if err != nil {
		writePanelError(w, http.StatusBadGateway, err.Error())
		return
	}
	if status == http.StatusMethodNotAllowed || status == http.StatusNotFound {
		raw, status, err = csqttBr.do(http.MethodPatch, path, payload)
		if err != nil {
			writePanelError(w, http.StatusBadGateway, err.Error())
			return
		}
	}
	if status >= 400 {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = fmt.Sprintf("CSQTT HTTP %d", status)
		}
		writePanelError(w, http.StatusBadRequest, msg)
		return
	}
	writePanelJSON(w, map[string]interface{}{
		"ok":         true,
		"password":   pass,
		"csqtt_link": csqttConnectLink(pass, peer, hashes),
		"label":      name,
	})
}
