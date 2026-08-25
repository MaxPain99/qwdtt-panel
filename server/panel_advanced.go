package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
)

type persistedSessions struct {
	Tokens map[string]time.Time `json:"tokens"`
}

var panelAuditMu sync.Mutex

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

func startPanelBackgroundTasks() {
	loadPanelSessions()
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
	cmd := exec.Command("certbot", "renew", "--quiet")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		writePanelError(w, http.StatusBadGateway, strings.TrimSpace(out.String()))
		return
	}
	panelAudit("tls_renew", "certbot renew")
	writePanelJSON(w, map[string]interface{}{
		"ok":      true,
		"message": "renew OK — при путях на live-файлы сертификат подхватится сам",
		"cert":    panelCertInfo(),
	})
}

func parseImportCSVReader(r io.Reader) ([]importClientRow, error) {
	br := bufio.NewReader(r)
	all, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	return parseImportRows("csv", string(all))
}
