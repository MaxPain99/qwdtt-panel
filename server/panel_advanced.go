package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

const (
	panelAuditFile        = "panel_audit.log"
	panelSessionsFile     = "panel_sessions.json"
	panelUpdateStatusFile = "/var/log/qwdtt-panel-update.status"
	panelNotifyInterval   = 5 * time.Minute
)

type panelNotifyConfig struct {
	TelegramToken  string `json:"telegram_token,omitempty"`
	TelegramChat   string `json:"telegram_chat,omitempty"`
	EmailTo        string `json:"email_to,omitempty"`
	EmailFrom      string `json:"email_from,omitempty"`
	SMTPServer     string `json:"smtp_server,omitempty"`
	WebhookURL     string `json:"webhook_url,omitempty"`
	OnHealthFail   bool   `json:"on_health_fail,omitempty"`
	OnClientExpiry bool   `json:"on_client_expiry,omitempty"`
	OnSocksBad     bool   `json:"on_socks_bad,omitempty"`
}

type persistedSessions struct {
	Tokens map[string]time.Time `json:"tokens"`
}

var (
	panelAuditMu     sync.Mutex
	panelNotifyMu    sync.Mutex
	lastHealthOK     = true
	lastSocksOK      = true
	notifiedExpiring = map[string]bool{}
)

func panelAudit(action, detail string) {
	panelAuditMu.Lock()
	defer panelAuditMu.Unlock()
	if panelDir == "" {
		return
	}
	line := fmt.Sprintf("%s\t%s\t%s\n", time.Now().Format(time.RFC3339), action, strings.ReplaceAll(detail, "\n", " "))
	f, err := os.OpenFile(filepath.Join(panelDir, panelAuditFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Close()
}

func loadPanelSessions() {
	if panelDir == "" {
		return
	}
	b, err := os.ReadFile(filepath.Join(panelDir, panelSessionsFile))
	if err != nil {
		return
	}
	var ps persistedSessions
	if json.Unmarshal(b, &ps) != nil || ps.Tokens == nil {
		return
	}
	now := time.Now()
	panelSessMu.Lock()
	for tok, exp := range ps.Tokens {
		if now.Before(exp) {
			panelSessions[tok] = exp
		}
	}
	panelSessMu.Unlock()
}

func savePanelSessions() {
	if panelDir == "" {
		return
	}
	panelSessMu.Lock()
	ps := persistedSessions{Tokens: map[string]time.Time{}}
	for k, v := range panelSessions {
		ps.Tokens[k] = v
	}
	panelSessMu.Unlock()
	b, _ := json.Marshal(ps)
	_ = os.WriteFile(filepath.Join(panelDir, panelSessionsFile), b, 0600)
}

func getPanelNotifySettings() panelNotifyConfig {
	panelStoreMu.Lock()
	defer panelStoreMu.Unlock()
	if panelStore == nil {
		return panelNotifyConfig{}
	}
	return panelStore.Notify
}

func startPanelBackgroundTasks() {
	loadPanelSessions()
	go panelNotifyLoop()
}

func panelNotifyLoop() {
	ticker := time.NewTicker(panelNotifyInterval)
	defer ticker.Stop()
	for range ticker.C {
		panelCheckNotifications()
	}
}

func panelCheckNotifications() {
	cfg := getPanelNotifySettings()
	if cfg.TelegramToken == "" && cfg.WebhookURL == "" && cfg.EmailTo == "" {
		return
	}
	wdttOK, _ := panelUnitActive("wdtt")
	panelOK, _ := panelUnitActive("qwdtt-panel")
	socksOn, _, _, socksHealth := socksSnapshot()
	healthOK := panelOK && wdttOK && (!socksOn || socksHealth == "" || socksHealth == "ok")

	panelNotifyMu.Lock()
	if cfg.OnHealthFail && lastHealthOK && !healthOK {
		panelSendNotify(cfg, "⚠️ qwdtt-panel: проблема со здоровьем сервисов")
	}
	if cfg.OnSocksBad && lastSocksOK && socksOn && socksHealth != "" && socksHealth != "ok" {
		panelSendNotify(cfg, "⚠️ SOCKS5: "+socksHealth)
	}
	lastHealthOK = healthOK
	lastSocksOK = !socksOn || socksHealth == "" || socksHealth == "ok"
	panelNotifyMu.Unlock()

	if !cfg.OnClientExpiry {
		return
	}
	now := time.Now()
	checkExp := func(pass, label, expStr string) {
		if expStr == "" {
			return
		}
		t, err := time.Parse("2006-01-02", expStr)
		if err != nil {
			return
		}
		days := int(t.Sub(now).Hours() / 24)
		if days < 0 || days > 3 {
			return
		}
		key := pass + ":" + expStr
		panelNotifyMu.Lock()
		if notifiedExpiring[key] {
			panelNotifyMu.Unlock()
			return
		}
		notifiedExpiring[key] = true
		panelNotifyMu.Unlock()
		msg := fmt.Sprintf("⏳ Клиент %s (%s) истекает %s (%d дн.)", label, pass, expStr, days)
		panelSendNotify(cfg, msg)
	}
	if panelWdttAdminEnabled() {
		if list, err := panelAdminListPasswords(); err == nil {
			for _, e := range list {
				exp := ""
				if e.ExpiresAt > 0 {
					exp = time.Unix(e.ExpiresAt, 0).Format("2006-01-02")
				}
				checkExp(e.Password, e.Label, exp)
			}
		}
	}
	if list, err := csqttListClients(); err == nil {
		for _, c := range list {
			pass, _ := c["password"].(string)
			label, _ := c["label"].(string)
			exp, _ := c["expires"].(string)
			checkExp(pass, label, exp)
		}
	}
}

func panelSendNotify(cfg panelNotifyConfig, text string) {
	if cfg.TelegramToken != "" && cfg.TelegramChat != "" {
		u := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", url.PathEscape(cfg.TelegramToken))
		body, _ := json.Marshal(map[string]string{"chat_id": cfg.TelegramChat, "text": text})
		req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		http.DefaultClient.Do(req)
	}
	if cfg.WebhookURL != "" {
		body, _ := json.Marshal(map[string]string{"text": text, "source": "qwdtt-panel"})
		req, _ := http.NewRequest(http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		http.DefaultClient.Do(req)
	}
	if cfg.EmailTo != "" && cfg.SMTPServer != "" {
		from := cfg.EmailFrom
		if from == "" {
			from = "panel@localhost"
		}
		msg := "Subject: qwdtt-panel alert\r\n\r\n" + text
		_ = smtp.SendMail(cfg.SMTPServer, nil, from, []string{cfg.EmailTo}, []byte(msg))
	}
}

func handlePanelMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	wdttOK, _ := panelUnitActive("wdtt")
	csqttOK, _ := panelUnitActive("csqtt")
	panelOK, _ := panelUnitActive("qwdtt-panel")
	socksOn, socksTCP, socksUDP, socksHealth := socksSnapshot()
	snap := panelServiceSnapshot()
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP qwdtt_panel_up Panel process reachable\n# TYPE qwdtt_panel_up gauge\nqwdtt_panel_up %d\n", bool01(panelOK))
	fmt.Fprintf(&b, "qwdtt_wdtt_up %d\n", bool01(wdttOK))
	fmt.Fprintf(&b, "qwdtt_csqtt_up %d\n", bool01(csqttOK))
	fmt.Fprintf(&b, "qwdtt_socks_on %d\n", bool01(socksOn))
	fmt.Fprintf(&b, "qwdtt_socks_tcp %d\n", socksTCP)
	fmt.Fprintf(&b, "qwdtt_socks_udp %d\n", socksUDP)
	fmt.Fprintf(&b, "qwdtt_socks_health_ok %d\n", bool01(!socksOn || socksHealth == "" || socksHealth == "ok"))
	if m, ok := snap["qwdtt"].(map[string]interface{}); ok {
		fmt.Fprintf(&b, "qwdtt_wdtt_admin_ok %d\n", bool01(m["admin_ok"] == true))
	}
	if m, ok := snap["csqtt"].(map[string]interface{}); ok {
		fmt.Fprintf(&b, "qwdtt_csqtt_api_ok %d\n", bool01(m["api_ok"] == true))
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(b.String()))
}

func bool01(v bool) int {
	if v {
		return 1
	}
	return 0
}

func handlePanelAudit(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	lines := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("lines")); err == nil && n > 0 && n <= 2000 {
		lines = n
	}
	text, _, _, err := tailFile(filepath.Join(panelDir, panelAuditFile), 96<<10)
	if err != nil {
		writePanelJSON(w, map[string]interface{}{"text": "", "empty": true})
		return
	}
	all := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	writePanelJSON(w, map[string]interface{}{"text": strings.Join(all, "\n"), "lines": len(all)})
}

func handlePanelNotifySettings(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg := getPanelNotifySettings()
		writePanelJSON(w, map[string]interface{}{
			"telegram_chat":    cfg.TelegramChat,
			"email_to":           cfg.EmailTo,
			"email_from":         cfg.EmailFrom,
			"smtp_server":        cfg.SMTPServer,
			"webhook_url":        cfg.WebhookURL,
			"on_health_fail":     cfg.OnHealthFail,
			"on_client_expiry":   cfg.OnClientExpiry,
			"on_socks_bad":       cfg.OnSocksBad,
			"has_telegram_token": cfg.TelegramToken != "",
		})
	case http.MethodPost:
		if err := parsePanelForm(r); err != nil {
			writePanelError(w, http.StatusBadRequest, "form")
			return
		}
		panelStoreMu.Lock()
		if panelStore == nil {
			panelStore = &panelFileStore{}
		}
		if v := r.FormValue("telegram_token"); v != "" {
			panelStore.Notify.TelegramToken = strings.TrimSpace(v)
		}
		panelStore.Notify.TelegramChat = strings.TrimSpace(r.FormValue("telegram_chat"))
		panelStore.Notify.EmailTo = strings.TrimSpace(r.FormValue("email_to"))
		panelStore.Notify.EmailFrom = strings.TrimSpace(r.FormValue("email_from"))
		panelStore.Notify.SMTPServer = strings.TrimSpace(r.FormValue("smtp_server"))
		panelStore.Notify.WebhookURL = strings.TrimSpace(r.FormValue("webhook_url"))
		panelStore.Notify.OnHealthFail = r.FormValue("on_health_fail") == "1"
		panelStore.Notify.OnClientExpiry = r.FormValue("on_client_expiry") == "1"
		panelStore.Notify.OnSocksBad = r.FormValue("on_socks_bad") == "1"
		panelStoreMu.Unlock()
		if err := persistPanelStore(); err != nil {
			writePanelError(w, http.StatusInternalServerError, err.Error())
			return
		}
		panelAudit("notify_settings", "updated")
		writePanelJSON(w, map[string]bool{"ok": true})
	default:
		writePanelError(w, http.StatusMethodNotAllowed, "method")
	}
}

func handlePanelQR(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	text := strings.TrimSpace(r.URL.Query().Get("text"))
	if text == "" {
		writePanelError(w, http.StatusBadRequest, "text")
		return
	}
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		writePanelError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

func handlePanelCsqttSettings(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		panelStoreMu.Lock()
		st := panelFileStore{}
		if panelStore != nil {
			st = *panelStore
		}
		panelStoreMu.Unlock()
		writePanelJSON(w, map[string]interface{}{
			"csqtt_url":  st.CsqttURL,
			"csqtt_user": st.CsqttUser,
			"has_pass":   st.CsqttPass != "",
		})
	case http.MethodPost:
		if err := parsePanelForm(r); err != nil {
			writePanelError(w, http.StatusBadRequest, "form")
			return
		}
		panelStoreMu.Lock()
		if panelStore == nil {
			panelStore = &panelFileStore{}
		}
		if v := strings.TrimSpace(r.FormValue("csqtt_url")); v != "" {
			panelStore.CsqttURL = v
		}
		if v := strings.TrimSpace(r.FormValue("csqtt_user")); v != "" {
			panelStore.CsqttUser = v
		}
		if v := r.FormValue("csqtt_pass"); v != "" {
			panelStore.CsqttPass = v
		}
		panelStoreMu.Unlock()
		if err := persistPanelStore(); err != nil {
			writePanelError(w, http.StatusInternalServerError, err.Error())
			return
		}
		panelApplyCsqttSettings()
		panelAudit("csqtt_settings", "updated")
		writePanelJSON(w, map[string]bool{"ok": true})
	default:
		writePanelError(w, http.StatusMethodNotAllowed, "method")
	}
}

func panelApplyCsqttSettings() {
	panelStoreMu.Lock()
	st := panelFileStore{}
	if panelStore != nil {
		st = *panelStore
	}
	panelStoreMu.Unlock()
	if st.CsqttURL == "" && st.CsqttUser == "" {
		return
	}
	csqttBr.mu.Lock()
	if st.CsqttURL != "" {
		csqttBr.base = strings.TrimRight(st.CsqttURL, "/")
	}
	if st.CsqttUser != "" {
		csqttBr.user = st.CsqttUser
	}
	if st.CsqttPass != "" {
		csqttBr.pass = st.CsqttPass
	}
	csqttBr.cookie = ""
	csqttBr.mu.Unlock()
}

func handlePanelClientsImport(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.FormValue("kind")))
	if kind == "" {
		kind = "qwdtt"
	}
	format := strings.ToLower(strings.TrimSpace(r.FormValue("format")))
	raw := strings.TrimSpace(r.FormValue("data"))
	if raw == "" {
		writePanelError(w, http.StatusBadRequest, "data")
		return
	}
	rows, err := parseImportRows(format, raw)
	if err != nil {
		writePanelError(w, http.StatusBadRequest, err.Error())
		return
	}
	created := 0
	var errs []string
	for _, row := range rows {
		if err := importOneClient(kind, row); err != nil {
			errs = append(errs, err.Error())
		} else {
			created++
		}
	}
	panelAudit("import", fmt.Sprintf("%s %d/%d", kind, created, len(rows)))
	writePanelJSON(w, map[string]interface{}{"ok": true, "created": created, "total": len(rows), "errors": errs})
}

type importClientRow struct {
	Label  string
	Hashes string
	Days   int
}

func parseImportRows(format, raw string) ([]importClientRow, error) {
	if format == "csv" {
		r := csv.NewReader(strings.NewReader(raw))
		recs, err := r.ReadAll()
		if err != nil {
			return nil, err
		}
		out := []importClientRow{}
		for i, rec := range recs {
			if len(rec) < 2 {
				continue
			}
			if i == 0 && strings.EqualFold(rec[0], "label") {
				continue
			}
			days := 30
			if len(rec) > 2 {
				if n, e := strconv.Atoi(strings.TrimSpace(rec[2])); e == nil {
					days = n
				}
			}
			out = append(out, importClientRow{Label: rec[0], Hashes: rec[1], Days: days})
		}
		return out, nil
	}
	var wrap struct {
		Clients []struct {
			Label  string `json:"label"`
			Hashes string `json:"hashes"`
			VkHash string `json:"vk_hash"`
			Days   int    `json:"days"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(raw), &wrap); err != nil {
		return nil, err
	}
	out := []importClientRow{}
	for _, c := range wrap.Clients {
		h := c.Hashes
		if h == "" {
			h = c.VkHash
		}
		days := c.Days
		if days <= 0 {
			days = 30
		}
		out = append(out, importClientRow{Label: c.Label, Hashes: h, Days: days})
	}
	return out, nil
}

func importOneClient(kind string, row importClientRow) error {
	if strings.TrimSpace(row.Hashes) == "" {
		return fmt.Errorf("%s: нет hash", row.Label)
	}
	if kind == "csqtt" {
		hashes, err := parseCsqttVkHashesFromString(row.Hashes)
		if err != nil {
			return err
		}
		payload := map[string]interface{}{
			"name": row.Label, "days": row.Days, "hash": hashes,
			"dtls_port": csqttDefaultPeer, "wg_port": 46001, "local_port": 0,
		}
		raw, status, err := csqttBr.do(http.MethodPost, "/api/clients", payload)
		if err != nil || status >= 400 {
			return fmt.Errorf("csqtt: %s", strings.TrimSpace(string(raw)))
		}
		return nil
	}
	if panelWdttAdminEnabled() {
		_, err := panelAdminCreatePassword(row.Label, row.Hashes, row.Days, 1)
		return err
	}
	return fmt.Errorf("qwdtt admin API не настроен")
}

func parseCsqttVkHashesFromString(s string) (string, error) {
	r, _ := http.NewRequest(http.MethodPost, "/", nil)
	r.Form = url.Values{"vk_hash": {s}}
	return parseCsqttVkHashes(r)
}

func handlePanelClientsBulk(w http.ResponseWriter, r *http.Request) {
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
	action := strings.TrimSpace(r.FormValue("action"))
	kind := strings.ToLower(strings.TrimSpace(r.FormValue("kind")))
	if kind == "" {
		kind = "qwdtt"
	}
	passes := strings.Split(strings.TrimSpace(r.FormValue("passwords")), ",")
	var list []string
	for _, p := range passes {
		p = strings.TrimSpace(p)
		if p != "" {
			list = append(list, p)
		}
	}
	if len(list) == 0 {
		writePanelError(w, http.StatusBadRequest, "passwords")
		return
	}
	ok := 0
	var errs []string
	for _, pass := range list {
		if err := bulkClientAction(kind, action, pass); err != nil {
			errs = append(errs, pass+": "+err.Error())
		} else {
			ok++
		}
	}
	panelAudit("bulk_"+action, fmt.Sprintf("%s %d/%d", kind, ok, len(list)))
	writePanelJSON(w, map[string]interface{}{"ok": ok, "total": len(list), "errors": errs})
}

func bulkClientAction(kind, action, pass string) error {
	switch action {
	case "activate":
		if kind == "csqtt" {
			_, st, err := csqttBr.do(http.MethodPost, "/api/clients/"+url.PathEscape(pass)+"/toggle", nil)
			if err != nil || st >= 400 {
				return fmt.Errorf("csqtt toggle")
			}
			return nil
		}
		if panelWdttAdminEnabled() {
			return panelAdminSetActive(pass, true)
		}
		return fmt.Errorf("admin API")
	case "deactivate":
		if kind == "csqtt" {
			_, st, err := csqttBr.do(http.MethodPost, "/api/clients/"+url.PathEscape(pass)+"/toggle", nil)
			if err != nil || st >= 400 {
				return fmt.Errorf("csqtt toggle")
			}
			return nil
		}
		if panelWdttAdminEnabled() {
			return panelAdminSetActive(pass, false)
		}
		return fmt.Errorf("admin API")
	case "delete":
		if kind == "csqtt" {
			_, st, err := csqttBr.do(http.MethodDelete, "/api/clients/"+url.PathEscape(pass), nil)
			if err != nil || st >= 400 {
				return fmt.Errorf("csqtt delete")
			}
			return nil
		}
		if panelWdttAdminEnabled() {
			return panelAdminDeletePassword(pass)
		}
		return fmt.Errorf("admin API")
	default:
		return fmt.Errorf("unknown action")
	}
}

func handlePanelResetTraffic(w http.ResponseWriter, r *http.Request) {
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
	kind := strings.ToLower(strings.TrimSpace(r.FormValue("kind")))
	if pass == "" {
		writePanelError(w, http.StatusBadRequest, "password")
		return
	}
	if kind == "csqtt" {
		payload := map[string]interface{}{"up": 0, "down": 0}
		_, st, err := csqttBr.do(http.MethodPatch, "/api/clients/"+url.PathEscape(pass), payload)
		if err != nil || st >= 400 {
			writePanelError(w, http.StatusBadGateway, "csqtt reset traffic")
			return
		}
		panelAudit("reset_traffic", "csqtt "+pass)
		writePanelJSON(w, map[string]bool{"ok": true})
		return
	}
	if panelWdttAdminEnabled() {
		if err := panelAdminResetTraffic(pass); err != nil {
			writePanelError(w, http.StatusBadGateway, err.Error())
			return
		}
		panelAudit("reset_traffic", "qwdtt "+pass)
		writePanelJSON(w, map[string]bool{"ok": true})
		return
	}
	dbMutex.Lock()
	entry, ok := db.Passwords[pass]
	if ok && entry != nil {
		entry.UpBytes = 0
		entry.DownBytes = 0
		saveDB()
	}
	dbMutex.Unlock()
	if !ok {
		writePanelError(w, http.StatusNotFound, "not found")
		return
	}
	panelAudit("reset_traffic", "local "+pass)
	writePanelJSON(w, map[string]bool{"ok": true})
}

func handlePanelCsqttUnbind(w http.ResponseWriter, r *http.Request) {
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
	payload := map[string]interface{}{"device_id": ""}
	raw, st, err := csqttBr.do(http.MethodPatch, "/api/clients/"+url.PathEscape(pass), payload)
	if err != nil || st >= 400 {
		writePanelError(w, http.StatusBadGateway, strings.TrimSpace(string(raw)))
		return
	}
	panelAudit("csqtt_unbind", pass)
	writePanelJSON(w, map[string]bool{"ok": true})
}

func handlePanelSocksProfiles(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		panelStoreMu.Lock()
		var profiles []SocksProfile
		active := ""
		if panelStore != nil {
			if len(panelStore.SocksProfiles) > 0 {
				profiles = append(profiles, panelStore.SocksProfiles...)
			} else if panelStore.Socks != nil {
				profiles = append(profiles, *panelStore.Socks)
			}
			active = panelStore.ActiveSocksID
		}
		panelStoreMu.Unlock()
		writePanelJSON(w, map[string]interface{}{"profiles": profiles, "active_id": active})
	case http.MethodPost:
		if err := parsePanelForm(r); err != nil {
			writePanelError(w, http.StatusBadRequest, "form")
			return
		}
		action := r.FormValue("action")
		panelStoreMu.Lock()
		if panelStore == nil {
			panelStore = &panelFileStore{}
		}
		switch action {
		case "add":
			p := SocksProfile{
				Host:     strings.TrimSpace(r.FormValue("host")),
				Port:     uint16(parseUint16(r.FormValue("port"), 1080)),
				Username: strings.TrimSpace(r.FormValue("username")),
				Password: r.FormValue("password"),
			}
			panelStore.SocksProfiles = append(panelStore.SocksProfiles, p)
		case "activate":
			idx, _ := strconv.Atoi(r.FormValue("index"))
			if idx >= 0 && idx < len(panelStore.SocksProfiles) {
				cp := panelStore.SocksProfiles[idx]
				panelStore.Socks = &cp
				panelStore.SocksOn = true
				panelStore.ActiveSocksID = strconv.Itoa(idx)
			}
		case "delete":
			idx, _ := strconv.Atoi(r.FormValue("index"))
			if idx >= 0 && idx < len(panelStore.SocksProfiles) {
				panelStore.SocksProfiles = append(panelStore.SocksProfiles[:idx], panelStore.SocksProfiles[idx+1:]...)
			}
		}
		panelStoreMu.Unlock()
		if err := persistPanelStore(); err != nil {
			writePanelError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if action == "activate" {
			panelStoreMu.Lock()
			if panelStore != nil && panelStore.Socks != nil {
				_ = socksSaveAndEnable(*panelStore.Socks)
			}
			panelStoreMu.Unlock()
		}
		writePanelJSON(w, map[string]bool{"ok": true})
	default:
		writePanelError(w, http.StatusMethodNotAllowed, "method")
	}
}

func parseUint16(s string, def uint16) uint16 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return def
	}
	return uint16(n)
}

func readUpdateJobStatus() string {
	b, err := os.ReadFile(panelUpdateStatusFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func enrichHealthResponse() map[string]interface{} {
	snap := panelServiceSnapshot()
	wdttOK, wdttState := panelUnitActive("wdtt")
	csqttOK, csqttState := panelUnitActive("csqtt")
	panelOK, panelState := panelUnitActive("qwdtt-panel")
	socksOn, _, _, socksHealth := socksSnapshot()
	csqttBridge := false
	if st := csqttCachedStatus(); st != nil {
		if v, ok := st["connected"].(bool); ok {
			csqttBridge = v
		}
	}
	wdttAdmin := panelWdttAdminEnabled() && panelAdminStatus() != nil
	ok := panelOK && (wdttOK || wdttAdmin) && (!csqttOK || csqttBridge) && (!socksOn || socksHealth == "" || socksHealth == "ok")
	out := map[string]interface{}{
		"ok": ok, "wdtt": wdttOK, "wdtt_state": wdttState, "wdtt_admin": wdttAdmin,
		"csqtt": csqttOK, "csqtt_state": csqttState, "csqtt_bridge": csqttBridge,
		"panel": panelOK, "panel_state": panelState,
		"socks_on": socksOn, "socks_health": socksHealth,
		"uptime": formatUptime(time.Since(serverStartTime)),
		"update_status": readUpdateJobStatus(),
	}
	if q, ok := snap["qwdtt"].(map[string]interface{}); ok {
		out["version_qwdtt"] = q["version"]
	}
	if q, ok := snap["csqtt"].(map[string]interface{}); ok {
		out["version_csqtt"] = q["version"]
	}
	if q, ok := snap["panel"].(map[string]interface{}); ok {
		out["version_panel"] = q["version"]
	}
	return out
}

func handlePanelTLSRenew(w http.ResponseWriter, r *http.Request) {
	if !requirePanelAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writePanelError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	if _, err := exec.LookPath("certbot"); err != nil {
		writePanelError(w, http.StatusBadRequest, "certbot не установлен")
		return
	}
	cmd := exec.Command("certbot", "renew", "--quiet", "--deploy-hook",
		fmt.Sprintf("cp /etc/letsencrypt/live/*/fullchain.pem %s && cp /etc/letsencrypt/live/*/privkey.pem %s",
			filepath.Join(panelDir, panelCertFile), filepath.Join(panelDir, panelKeyFile)))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		writePanelError(w, http.StatusBadGateway, strings.TrimSpace(out.String()))
		return
	}
	panelAudit("tls_renew", "certbot renew")
	writePanelJSON(w, map[string]interface{}{"ok": true, "message": "renew OK — перезапустите панель"})
}

func parseImportCSVReader(r io.Reader) ([]importClientRow, error) {
	br := bufio.NewReader(r)
	all, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	return parseImportRows("csv", string(all))
}
